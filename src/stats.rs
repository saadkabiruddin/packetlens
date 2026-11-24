//! Per-packet decoding summary and running statistics, shared by the CLI and the GUI.
use crate::{ethernet, ipv4, transport, Transport};
use std::{collections::BTreeMap, net::Ipv4Addr};

pub fn mac(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":") }

/// What could be decoded from one packet. Fields are `None` where decoding stopped.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// 1-based packet number.
    pub index: u64,
    pub captured_len: usize,
    pub original_len: u32,
    pub truncated: bool,
    /// (source MAC, destination MAC, EtherType)
    pub link: Option<([u8; 6], [u8; 6], u16)>,
    /// (source, destination) for IPv4 packets.
    pub addresses: Option<(Ipv4Addr, Ipv4Addr)>,
    /// (source port, destination port) for TCP and UDP.
    pub ports: Option<(u16, u16)>,
    /// Protocol label used in the distribution, or "Malformed".
    pub protocol: String,
    /// Transport details; `Some` only when the transport layer was decoded.
    pub detail: Option<String>,
    pub error: Option<&'static str>,
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub count: u64,
    pub bytes: u64,
    pub invalid: u64,
    pub truncated: u64,
    pub fragments: u64,
    pub protocols: BTreeMap<String, u64>,
    pub sources: BTreeMap<String, u64>,
}

impl Stats {
    /// Decodes one packet, updates the counters and returns what was decoded.
    pub fn packet(&mut self, data: &[u8], original_len: u32) -> PacketInfo {
        self.count += 1;
        self.bytes += data.len() as u64;
        let truncated = data.len() < original_len as usize;
        if truncated { self.truncated += 1; }
        let mut info = PacketInfo {
            index: self.count, captured_len: data.len(), original_len, truncated,
            link: None, addresses: None, ports: None, protocol: "Malformed".into(), detail: None, error: None,
        };
        if let Err(e) = self.decode(data, &mut info) {
            if !truncated { self.invalid += 1; }
            info.error = Some(e);
        }
        info
    }

    fn decode(&mut self, data: &[u8], info: &mut PacketInfo) -> Result<(), &'static str> {
        let e = ethernet(data)?;
        info.link = Some((e.source, e.destination, e.ethertype));
        if e.ethertype != 0x0800 {
            info.protocol = match e.ethertype {
                0x0806 => "ARP".into(),
                0x86dd => "IPv6 (not parsed)".into(),
                n => format!("EtherType 0x{n:04X}"),
            };
            *self.protocols.entry(info.protocol.clone()).or_default() += 1;
            return Ok(());
        }
        let ip = ipv4(e.payload)?;
        info.addresses = Some((ip.source, ip.destination));
        *self.sources.entry(ip.source.to_string()).or_default() += 1;
        if ip.fragmented {
            self.fragments += 1;
            info.protocol = "IPv4 fragment".into();
            *self.protocols.entry(info.protocol.clone()).or_default() += 1;
            return Ok(());
        }
        let (name, detail) = match transport(ip.protocol, ip.payload)? {
            Transport::Tcp { source, destination, flags, payload } => {
                info.ports = Some((source, destination));
                ("TCP".into(), format!("{source} -> {destination} | flags 0x{flags:02X} | {} payload bytes", payload.len()))
            }
            Transport::Udp { source, destination, payload } => {
                info.ports = Some((source, destination));
                ("UDP".into(), format!("{source} -> {destination} | {} payload bytes", payload.len()))
            }
            Transport::Icmp { kind, code } => ("ICMP".into(), format!("type {kind}, code {code}")),
            Transport::Other(n) => (format!("IP protocol {n}"), String::new()),
        };
        info.protocol = name;
        info.detail = Some(detail);
        *self.protocols.entry(info.protocol.clone()).or_default() += 1;
        Ok(())
    }

    pub fn report(&self) -> String {
        let Self { count, bytes, invalid, truncated, fragments, protocols, sources } = self;
        let mut s = format!("\nPackets: {count}\nCaptured bytes: {bytes}\nMalformed packets: {invalid}\nTruncated captures: {truncated}\nIPv4 fragments: {fragments}\n\nProtocol distribution:\n");
        for (name, n) in protocols { s += &format!("  {name}: {n}\n"); }
        s += "\nSource IPv4 addresses:\n";
        for (ip, n) in sources { s += &format!("  {ip}: {n}\n"); }
        s
    }
}

impl PacketInfo {
    /// The CLI's `--verbose` lines for this packet.
    pub fn verbose_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some((src, dst, kind)) = self.link {
            lines.push(format!("#{} {} bytes | {} -> {} | EtherType 0x{kind:04X}", self.index, self.captured_len, mac(&src), mac(&dst)));
        }
        if let (Some((src, dst)), Some(detail)) = (self.addresses, &self.detail) {
            lines.push(format!("  {src} -> {dst} | {} {detail}", self.protocol));
        }
        if let Some(e) = self.error {
            lines.push(format!("  Parse error: {e}{}", if self.truncated { " (capture truncated)" } else { "" }));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn sample_stats() {
        let mut p = crate::Pcap::new(&include_bytes!("../captures/sample.pcap")[..]).unwrap();
        let mut s = Stats::default();
        let mut infos = Vec::new();
        while let Some(r) = p.next_record().unwrap() { infos.push(s.packet(&r.data, r.original_len)); }
        assert_eq!((s.count, s.bytes, s.invalid), (3, 180, 0));
        assert_eq!(infos[0].protocol, "TCP");
        assert_eq!(infos[0].ports, Some((12345, 443)));
        assert_eq!(infos[2].protocol, "ICMP");
    }
    #[test] fn malformed_counted() {
        let mut s = Stats::default();
        let info = s.packet(&[0u8; 10], 10);
        assert_eq!((s.invalid, info.protocol.as_str(), info.error), (1, "Malformed", Some("short Ethernet header")));
    }
}
