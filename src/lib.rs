use std::net::Ipv4Addr;
use std::io::{self, Read};
pub mod stats;
pub use stats::{PacketInfo, Stats};

#[derive(Debug, PartialEq)]
pub struct Ethernet<'a> {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}
fn be16(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }
pub fn ethernet(b: &[u8]) -> Result<Ethernet<'_>, &'static str> {
    if b.len() < 14 { return Err("short Ethernet header"); }
    let mut kind = be16(&b[12..]);
    let mut offset = 14;
    while matches!(kind, 0x8100 | 0x88a8) {
        if b.len() < offset + 4 { return Err("short VLAN header"); }
        kind = be16(&b[offset+2..]);
        offset += 4;
    }
    Ok(Ethernet { destination: b[..6].try_into().unwrap(), source: b[6..12].try_into().unwrap(), ethertype: kind, payload: &b[offset..] })
}
#[derive(Debug, PartialEq)]
pub struct Ipv4<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    pub fragmented: bool,
    pub payload: &'a [u8],
}
pub fn ipv4(b: &[u8]) -> Result<Ipv4<'_>, &'static str> {
    if b.len() < 20 || b[0] >> 4 != 4 { return Err("invalid IPv4 header"); }
    let header = usize::from(b[0] & 15) * 4;
    let total = usize::from(be16(&b[2..]));
    if header < 20 || total < header || total > b.len() { return Err("invalid or truncated IPv4 length"); }
    Ok(Ipv4 { source: Ipv4Addr::new(b[12],b[13],b[14],b[15]), destination: Ipv4Addr::new(b[16],b[17],b[18],b[19]), protocol: b[9], fragmented: be16(&b[6..]) & 0x3fff != 0, payload: &b[header..total] })
}
#[derive(Debug, PartialEq)]
pub enum Transport<'a> {
    Tcp { source: u16, destination: u16, flags: u8, payload: &'a [u8] },
    Udp { source: u16, destination: u16, payload: &'a [u8] },
    Icmp { kind: u8, code: u8 },
    Other(u8),
}
pub fn transport(protocol: u8, b: &[u8]) -> Result<Transport<'_>, &'static str> {
    match protocol {
        6 => {
            if b.len() < 20 { return Err("short TCP header"); }
            let h = usize::from(b[12] >> 4)*4;
            if h < 20 || h > b.len() { return Err("invalid TCP header length"); }
            Ok(Transport::Tcp { source: be16(b), destination: be16(&b[2..]), flags: b[13], payload: &b[h..] })
        }
        17 => {
            if b.len() < 8 { return Err("short UDP header"); }
            let n = usize::from(be16(&b[4..]));
            if n < 8 || n > b.len() { return Err("invalid UDP length"); }
            Ok(Transport::Udp { source: be16(b), destination: be16(&b[2..]), payload: &b[8..n] })
        }
        1 => { if b.len() < 8 { return Err("short ICMP header"); } Ok(Transport::Icmp { kind: b[0], code: b[1] }) }
        n => Ok(Transport::Other(n)),
    }
}
fn invalid(s: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, s) }
pub struct Pcap<R> { reader: R, little: bool, pub nanoseconds: bool, snaplen: u32 }
#[derive(Debug)]
pub struct Record { pub seconds: u32, pub fraction: u32, pub original_len: u32, pub data: Vec<u8> }
impl<R: Read> Pcap<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut h = [0u8;24]; reader.read_exact(&mut h)?;
        let (little,nanoseconds) = match &h[..4] {
            [0xd4,0xc3,0xb2,0xa1] => (true,false), [0xa1,0xb2,0xc3,0xd4] => (false,false),
            [0x4d,0x3c,0xb2,0xa1] => (true,true), [0xa1,0xb2,0x3c,0x4d] => (false,true),
            _ => return Err(invalid("unsupported format: expected classic PCAP, not PCAPNG")),
        };
        let u16at = |i: usize| { let a = [h[i],h[i+1]]; if little {u16::from_le_bytes(a)} else {u16::from_be_bytes(a)} };
        let u32at = |i: usize| { let a = [h[i],h[i+1],h[i+2],h[i+3]]; if little {u32::from_le_bytes(a)} else {u32::from_be_bytes(a)} };
        if (u16at(4),u16at(6)) != (2,4) { return Err(invalid("unsupported PCAP version")); }
        if u32at(20) & 0xffff != 1 { return Err(invalid("only Ethernet link type is supported")); }
        let snaplen = u32at(16); if snaplen == 0 { return Err(invalid("invalid snaplen")); }
        Ok(Self { reader, little, nanoseconds, snaplen })
    }
    pub fn next_record(&mut self) -> io::Result<Option<Record>> {
        let mut h = [0u8;16];
        if self.reader.read(&mut h[..1])? == 0 { return Ok(None); }
        self.reader.read_exact(&mut h[1..])?;
        let little = self.little;
        let at = |i: usize| { let a = [h[i],h[i+1],h[i+2],h[i+3]]; if little {u32::from_le_bytes(a)} else {u32::from_be_bytes(a)} };
        let n = at(8); let original_len = at(12);
        if n > self.snaplen || n > original_len || n > 16*1024*1024 { return Err(invalid("invalid or excessive capture length")); }
        let fraction = at(4);
        if fraction >= if self.nanoseconds {1_000_000_000} else {1_000_000} { return Err(invalid("invalid timestamp")); }
        let mut data = vec![0; n as usize]; self.reader.read_exact(&mut data)?;
        Ok(Some(Record { seconds: at(0), fraction, original_len, data }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn ethernet_header() { let b = [0xff,0xff,0xff,0xff,0xff,0xff,0,1,2,3,4,5,8,0]; let e=ethernet(&b).unwrap(); assert_eq!(e.ethertype,0x0800); assert_eq!(e.source,[0,1,2,3,4,5]); assert!(ethernet(&b[..13]).is_err()); }
    #[test] fn udp_lengths() { let b=[0,53,0,80,0,9,0,0,42]; assert_eq!(transport(17,&b).unwrap(),Transport::Udp{source:53,destination:80,payload:&[42]}); assert!(transport(17,&b[..8]).is_err()); }
    #[test] fn ipv4_invalid() { assert!(ipv4(&[0;20]).is_err()); let mut b=[0;20]; b[0]=0x45;b[3]=20;assert!(ipv4(&b).is_ok()); b[3]=21;assert!(ipv4(&b).is_err()); }
    #[test] fn sample_capture() { let mut p=Pcap::new(&include_bytes!("../captures/sample.pcap")[..]).unwrap(); for protocol in [6,17,1] { let r=p.next_record().unwrap().unwrap(); let e=ethernet(&r.data).unwrap(); let ip=ipv4(e.payload).unwrap(); assert_eq!(ip.protocol,protocol); assert!(transport(ip.protocol,ip.payload).is_ok()); } assert!(p.next_record().unwrap().is_none()); }
    #[test] fn short_capture() { assert!(Pcap::new(&[0u8;3][..]).is_err()); }
}
