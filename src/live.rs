use super::packet;
use packetlens::Stats;
use pcap::{Capture, Device, Error, Linktype};
use std::{error::Error as StdError, time::{Duration, Instant}};

type Outcome = Result<(), Box<dyn StdError>>;

pub fn interfaces() -> Outcome {
    for (i, device) in Device::list()?.iter().enumerate() {
        println!("{}: {} — {}", i+1, device.name, device.desc.as_deref().unwrap_or(""));
    }
    Ok(())
}

pub fn run(args: &[String]) -> Outcome {
    let index: usize = args.first().ok_or("missing interface number")?.parse()?;
    let mut count = 100u64;
    let mut verbose = false;
    let mut count_set = false;
    for arg in &args[1..] {
        if arg == "--verbose" { verbose = true; }
        else if !count_set { count = arg.parse()?; count_set = true; }
        else { return Err("unexpected argument".into()); }
    }
    if count == 0 { return Err("packet count must be positive".into()); }
    let device = Device::list()?.into_iter().nth(index.checked_sub(1).ok_or("interface numbers start at 1")?).ok_or("interface not found")?;
    println!("Capturing on {} (up to {count} packets or 30 seconds)", device.name);
    let cap = Capture::from_device(device)?.promisc(false).snaplen(65535).timeout(250).open()?;
    if cap.get_datalink() != Linktype::ETHERNET { return Err("only Ethernet link type is supported; choose another interface".into()); }
    let mut cap = cap.setnonblock()?;
    let mut stats = Stats::default();
    let start = Instant::now();
    let mut last = start;
    while stats.count < count && start.elapsed() < Duration::from_secs(30) {
        match cap.next_packet() {
            Ok(p) => packet(&mut stats, p.data, p.header.len, verbose),
            Err(Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => { print!("{}", stats.report()); return Err(e.into()); }
        }
        if last.elapsed() >= Duration::from_secs(1) {
            println!("Live: {} packets | {} captured bytes", stats.count, stats.bytes);
            last = Instant::now();
        }
    }
    print!("{}", stats.report());
    Ok(())
}
