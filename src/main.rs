use packetlens::{Pcap, Stats};
use std::{env, fs::File, io::{self, BufReader}};
fn packet(stats:&mut Stats, data:&[u8], original_len:u32, verbose:bool) {
    let info=stats.packet(data,original_len);
    if verbose { for line in info.verbose_lines() { println!("{line}"); } }
}
fn analyze(path:&str, verbose:bool)->io::Result<()> {
    let mut p=Pcap::new(BufReader::new(File::open(path)?))?;
    let mut stats=Stats::default();
    println!("PacketLens v1.1.0\nCapture: {path}");
    while let Some(r)=p.next_record()? { packet(&mut stats,&r.data,r.original_len,verbose); }
    print!("{}",stats.report()); Ok(())
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
