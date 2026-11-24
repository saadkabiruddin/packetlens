use packetlens::{ethernet, ipv4, transport, Pcap, Transport};
use std::{collections::BTreeMap, env, fs::File, io::{self, BufReader}};
fn mac(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":") }
#[derive(Default)]
struct Stats { count:u64, bytes:u64, invalid:u64, truncated:u64, fragments:u64, protocols:BTreeMap<String,u64>, sources:BTreeMap<String,u64> }
impl Stats {
    fn packet(&mut self, data:&[u8], original_len:u32, verbose:bool) {
        let Self {count,bytes,invalid,truncated,fragments,protocols,sources}=self;
        *count += 1; *bytes += data.len() as u64;
        let cut = data.len() < original_len as usize;
        if cut { *truncated += 1; }
        let decoded = (|| -> Result<(), &'static str> {
            let e = ethernet(data)?;
            if verbose { println!("#{count} {} bytes | {} -> {} | EtherType 0x{:04X}", data.len(),mac(&e.source),mac(&e.destination),e.ethertype); }
            if e.ethertype != 0x0800 {
                let name = match e.ethertype {0x0806=>"ARP".into(),0x86dd=>"IPv6 (not parsed)".into(),n=>format!("EtherType 0x{n:04X}")};
                *protocols.entry(name).or_default() += 1; return Ok(());
            }
            let ip = ipv4(e.payload)?;
            *sources.entry(ip.source.to_string()).or_default() += 1;
            if ip.fragmented { *fragments += 1; *protocols.entry("IPv4 fragment".into()).or_default() += 1; return Ok(()); }
            let (name,detail) = match transport(ip.protocol,ip.payload)? {
                Transport::Tcp{source,destination,flags,payload} => ("TCP".into(),format!("{source} -> {destination} | flags 0x{flags:02X} | {} payload bytes",payload.len())),
                Transport::Udp{source,destination,payload} => ("UDP".into(),format!("{source} -> {destination} | {} payload bytes",payload.len())),
                Transport::Icmp{kind,code} => ("ICMP".into(),format!("type {kind}, code {code}")),
                Transport::Other(n) => (format!("IP protocol {n}"),String::new()),
            };
            if verbose { println!("  {} -> {} | {name} {detail}",ip.source,ip.destination); }
            *protocols.entry(name).or_default() += 1; Ok(())
        })();
        if let Err(e) = decoded { if !cut { *invalid += 1; } if verbose { println!("  Parse error: {e}{}",if cut {" (capture truncated)"} else {""}); } }
    }
    fn report(&self) {
        let Self {count,bytes,invalid,truncated,fragments,protocols,sources}=self;
    println!("\nPackets: {count}\nCaptured bytes: {bytes}\nMalformed packets: {invalid}\nTruncated captures: {truncated}\nIPv4 fragments: {fragments}\n\nProtocol distribution:");
    for (name,n) in protocols { println!("  {name}: {n}"); }
    println!("\nSource IPv4 addresses:"); for (ip,n) in sources { println!("  {ip}: {n}"); }
    }
}
fn analyze(path:&str, verbose:bool)->io::Result<()> {
    let mut p=Pcap::new(BufReader::new(File::open(path)?))?;
    let mut stats=Stats::default();
    println!("PacketLens v1.1.0\nCapture: {path}");
    while let Some(r)=p.next_record()? { stats.packet(&r.data,r.original_len,verbose); }
    stats.report(); Ok(())
}
#[cfg(feature="live")]
mod live;
const USAGE:&str="Usage:\n  packetlens analyze <capture.pcap> [--verbose]\n  packetlens interfaces\n  packetlens live <interface-number> [packet-count] [--verbose]\nLive commands require --features live. Default count: 100.";
fn run(args:&[String])->Result<(),Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("--help"|"-h") => {println!("{USAGE}"); Ok(())},
        Some("analyze") if args.len()==2 || (args.len()==3 && args[2]=="--verbose") => {analyze(&args[1],args.len()==3)?; Ok(())},
        #[cfg(feature="live")]
        Some("interfaces") if args.len()==1 => live::interfaces(),
        #[cfg(feature="live")]
        Some("live") => live::run(&args[1..]),
        _ => Err(USAGE.into()),
    }
}
fn main()->std::process::ExitCode {
    let args:Vec<String>=env::args().skip(1).collect();
    match run(&args) {Ok(())=>std::process::ExitCode::SUCCESS,Err(e)=>{eprintln!("Error: {e}");std::process::ExitCode::FAILURE}}
}
