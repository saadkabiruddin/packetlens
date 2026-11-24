# PacketLens
Dependency-free Rust CLI for offline Ethernet/IPv4 packet inspection.

## Run
Install Rust using rustup. From this directory:

```sh
cargo run -- analyze captures/sample.pcap --verbose
cargo test
cargo build --release
```

The synthetic capture contains one TCP, one UDP and one ICMP packet (180 captured bytes total). No real user traffic is included. Classic PCAP, Ethernet link type only; Wireshark can export classic PCAP rather than PCAPNG. Analyze only captures you are authorized to inspect.

## Architecture
`src/lib.rs` contains PCAP reading and Ethernet, IPv4 and transport parsing. `src/main.rs` handles CLI and statistics. Each parser validates lengths before indexing and borrows payload slices. PCAP records are read one at a time, with a 16 MiB per-record allocation cap.

## Limitations
No live capture, IPv6 decoding, fragment reassembly, checksum validation, encrypted payload decoding or full protocol conformance validation. Truncated capture records are counted separately from malformed packets. The malformed count reflects structural parsing checks, not proof of malicious traffic. Source-address statistics grow with unique addresses. The sample is synthetic; performance and accuracy on real traffic are not benchmarked.

## Live capture (v1.1)

Offline commands still work without native capture libraries. For live capture, install Npcap and its SDK on Windows (https://npcap.com/#download), then extract the SDK into this directory as `npcap-sdk-<version>` (git-ignored) or set `$env:NPCAP_SDK` to its folder; `build.rs` adds the right `Lib` folder to the linker path. On Fedora install `libpcap-devel` and `pkgconf-pkg-config`.

```
cargo run --features live -- interfaces
cargo run --features live -- live 1 100 --verbose
```

Choose the actual adapter number from the list. The capture stops after 100 packets (or your specified count) or 30 seconds, whichever comes first. It uses non-promiscuous mode and does not write captures to disk. Capture only on networks and devices you are authorized to monitor. IPv6 is identified but not decoded; only Ethernet link types are supported. Live capture requires native driver permissions. Tests: `cargo test` and `cargo test --features live`.
