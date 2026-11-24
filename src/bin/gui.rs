//! PacketLens desktop window: live capture and .pcap viewing.
//! Run with `cargo run --features gui --bin packetlens-gui`.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Line, Plot, PlotPoints};
use packetlens::{stats::mac, PacketInfo, Pcap, Stats};
use std::{
    collections::VecDeque,
    fs::File,
    io::BufReader,
    sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc},
    thread,
    time::Duration,
};

/// Oldest rows are dropped past this so a long capture can't use unbounded memory.
const MAX_ROWS: usize = 100_000;
/// Packets taken from the channel per frame, so the window stays responsive under load.
const MAX_PER_FRAME: usize = 20_000;

fn main() -> eframe::Result {
    // eframe also tries OpenGL by default, which crashes on some Windows drivers.
    // Use DX12/Vulkan/Metal only, unless WGPU_BACKEND says otherwise.
    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut wgpu_options.wgpu_setup {
        setup.instance_descriptor.backends = eframe::wgpu::Backends::from_env().unwrap_or(eframe::wgpu::Backends::PRIMARY);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]).with_min_inner_size([800.0, 500.0]),
        wgpu_options,
        ..Default::default()
    };
    eframe::run_native("PacketLens", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}

enum Msg {
    Packet { time: f64, data: Vec<u8>, original_len: u32 },
    Error(String),
    Done,
}

/// A running live capture or file read on a background thread.
struct Job {
    stop: Arc<AtomicBool>,
    rx: mpsc::Receiver<Msg>,
    live: bool,
}

struct Row {
    time: f64,
    info: PacketInfo,
    data: Vec<u8>,
    /// Lowercase protocol and addresses, for the filter box.
    search: String,
}

struct Adapter { device: pcap::Device, label: String }

struct App {
    adapters: Vec<Adapter>,
    adapter: usize,
    job: Option<Job>,
    source: String,
    rows: VecDeque<Row>,
    stats: Stats,
    first_time: Option<f64>,
    per_second: Vec<u64>,
    filter: String,
    selected: Option<u64>,
    follow: bool,
    status: String,
    error: Option<String>,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            adapters: Vec::new(), adapter: 0, job: None, source: String::new(), rows: VecDeque::new(),
            stats: Stats::default(), first_time: None, per_second: Vec::new(), filter: String::new(),
            selected: None, follow: true, status: "Ready".into(), error: None,
        };
        app.refresh_adapters();
        app
    }

    fn refresh_adapters(&mut self) {
        match pcap::Device::list() {
            Ok(list) => {
                self.adapters = list.into_iter().map(|device| {
                    let desc = device.desc.clone().unwrap_or_else(|| device.name.clone());
                    let ip = device.addresses.iter().find(|a| a.addr.is_ipv4()).map(|a| format!(" ({})", a.addr)).unwrap_or_default();
                    Adapter { label: format!("{desc}{ip}"), device }
                }).collect();
                // Preselect the adapter carrying the default route; virtual adapters (Hyper-V, WSL, VPN)
                // can also be up with an IPv4 address but see none of the normal traffic.
                let route = default_route_address();
                let up = |a: &Adapter| { let f = &a.device.flags; f.is_up() && f.is_running() && !f.is_loopback() && a.device.addresses.iter().any(|x| x.addr.is_ipv4()) };
                self.adapter = route.and_then(|ip| self.adapters.iter().position(|a| a.device.addresses.iter().any(|x| x.addr == ip)))
                    .or_else(|| self.adapters.iter().position(|a| up(a) && !a.label.to_lowercase().contains("virtual")))
                    .or_else(|| self.adapters.iter().position(up))
                    .unwrap_or(0);
                if self.adapters.is_empty() { self.error = Some("No capture adapters found. Is Npcap installed?".into()); }
            }
            Err(e) => self.error = Some(format!("Could not list adapters: {e}. Is Npcap installed?")),
        }
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.stats = Stats::default();
        self.first_time = None;
        self.per_second.clear();
        self.selected = None;
        self.error = None;
    }

    fn start_live(&mut self, ctx: &egui::Context) {
        let Some(adapter) = self.adapters.get(self.adapter) else { return };
        let (label, device) = (adapter.label.clone(), adapter.device.clone());
        self.stop();
        self.clear();
        self.source = label;
        self.job = Some(spawn(ctx, true, move |stop, tx| {
            let mut cap = pcap::Capture::from_device(device).and_then(|c| c.promisc(false).snaplen(65535).timeout(100).immediate_mode(true).open())
                .map_err(|e| format!("Could not open adapter: {e}. Try running as Administrator."))?;
            if cap.get_datalink() != pcap::Linktype::ETHERNET {
                return Err("Only Ethernet adapters are supported; choose another adapter.".into());
            }
            while !stop.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(p) => {
                        let time = p.header.ts.tv_sec as f64 + p.header.ts.tv_usec as f64 / 1e6;
                        if tx.send(Msg::Packet { time, data: p.data.to_vec(), original_len: p.header.len }).is_err() { break; }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(())
        }));
        self.status = "Capturing".into();
    }

    fn open_file(&mut self, ctx: &egui::Context) {
        let Some(path) = rfd::FileDialog::new().add_filter("PCAP capture", &["pcap", "cap"]).add_filter("All files", &["*"]).pick_file() else { return };
        self.stop();
        self.clear();
        self.source = path.display().to_string();
        self.job = Some(spawn(ctx, false, move |stop, tx| {
            let mut pcap = Pcap::new(BufReader::new(File::open(&path).map_err(|e| e.to_string())?)).map_err(|e| e.to_string())?;
            let scale = if pcap.nanoseconds { 1e9 } else { 1e6 };
            while !stop.load(Ordering::Relaxed) {
                let Some(r) = pcap.next_record().map_err(|e| e.to_string())? else { break };
                let time = r.seconds as f64 + r.fraction as f64 / scale;
                if tx.send(Msg::Packet { time, data: r.data, original_len: r.original_len }).is_err() { break; }
            }
            Ok(())
        }));
        self.status = "Reading file".into();
    }

    fn stop(&mut self) {
        if let Some(job) = &self.job { job.stop.store(true, Ordering::Relaxed); }
    }

    /// Moves packets from the background thread into the table and statistics.
    fn drain(&mut self) {
        let Some(job) = &self.job else { return };
        let mut finished = false;
        for msg in job.rx.try_iter().take(MAX_PER_FRAME) {
            match msg {
                Msg::Packet { time, data, original_len } => {
                    let first = *self.first_time.get_or_insert(time);
                    let time = (time - first).max(0.0);
                    let second = time as usize;
                    if second < 86_400 {
                        if self.per_second.len() <= second { self.per_second.resize(second + 1, 0); }
                        self.per_second[second] += 1;
                    }
                    let info = self.stats.packet(&data, original_len);
                    let mut search = info.protocol.to_lowercase();
                    if let Some((s, d)) = info.addresses { search += &format!(" {s} {d}"); }
                    self.rows.push_back(Row { time, info, data, search });
                    if self.rows.len() > MAX_ROWS { self.rows.pop_front(); }
                }
                Msg::Error(e) => self.error = Some(e),
                Msg::Done => finished = true,
            }
        }
        if finished {
            self.status = if job.live { "Capture stopped".into() } else { "File loaded".into() };
            self.job = None;
        }
    }

    fn row_by_index(&self, index: u64) -> Option<&Row> {
        let front = self.rows.front()?.info.index;
        self.rows.get(index.checked_sub(front)? as usize)
    }
}

/// The local IPv4 address the OS would use to reach the internet. A UDP `connect` only selects
/// a route; no packet is sent.
fn default_route_address() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Runs `work` on a background thread, then reports its error (if any) and completion.
fn spawn(ctx: &egui::Context, live: bool, work: impl FnOnce(&AtomicBool, &mpsc::Sender<Msg>) -> Result<(), String> + Send + 'static) -> Job {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_stop, ctx) = (stop.clone(), ctx.clone());
    thread::spawn(move || {
        if let Err(e) = work(&thread_stop, &tx) { let _ = tx.send(Msg::Error(e)); }
        let _ = tx.send(Msg::Done);
        ctx.request_repaint();
    });
    Job { stop, rx, live }
}

/// Filter terms are ANDed: protocol names, IP address fragments, or `port N`.
fn matches(filter: &str, row: &Row) -> bool {
    let mut terms = filter.split_whitespace();
    while let Some(term) = terms.next() {
        let ok = if term.eq_ignore_ascii_case("port") {
            match terms.next().and_then(|p| p.parse::<u16>().ok()) {
                Some(p) => row.info.ports.is_some_and(|(s, d)| s == p || d == p),
                None => false,
            }
        } else {
            row.search.contains(&term.to_lowercase())
        };
        if !ok { return false; }
    }
    true
}

fn protocol_color(protocol: &str) -> Color32 {
    match protocol {
        "TCP" => Color32::from_rgb(110, 170, 255),
        "UDP" => Color32::from_rgb(120, 210, 140),
        "ICMP" => Color32::from_rgb(240, 190, 90),
        "ARP" => Color32::from_rgb(200, 150, 240),
        "Malformed" => Color32::from_rgb(240, 100, 100),
        _ => Color32::GRAY,
    }
}

fn hex_dump(data: &[u8]) -> String {
    data.chunks(16).enumerate().map(|(i, chunk)| {
        let hex: String = (0..16).map(|j| chunk.get(j).map_or("   ".into(), |b| format!("{b:02X} "))).collect();
        let ascii: String = chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        format!("{:04X}  {hex} {ascii}", i * 16)
    }).collect::<Vec<_>>().join("\n")
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain();
        if self.job.is_some() { ctx.request_repaint_after(Duration::from_millis(100)); }
        let busy = self.job.is_some();

        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("PacketLens");
                ui.separator();
                ui.label("Adapter:");
                let current = self.adapters.get(self.adapter).map_or("(none)".to_string(), |a| a.label.clone());
                ui.add_enabled_ui(!busy, |ui| {
                    egui::ComboBox::from_id_salt("adapter").width(340.0).selected_text(current).show_ui(ui, |ui| {
                        for (i, a) in self.adapters.iter().enumerate() { ui.selectable_value(&mut self.adapter, i, &a.label); }
                    });
                    if ui.button("⟳").on_hover_text("Refresh adapter list").clicked() { self.refresh_adapters(); }
                });
                if busy {
                    if ui.button(RichText::new("■ Stop").color(Color32::from_rgb(240, 110, 110))).clicked() { self.stop(); }
                } else if ui.add_enabled(!self.adapters.is_empty(), egui::Button::new(RichText::new("▶ Start capture").color(Color32::from_rgb(120, 210, 140)))).clicked() {
                    self.start_live(&ctx);
                }
                ui.add_enabled_ui(!busy, |ui| {
                    if ui.button("📂 Open .pcap…").clicked() { self.open_file(&ctx); }
                    if ui.button("Clear").clicked() { self.clear(); self.source.clear(); }
                });
            });
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("e.g.  tcp   udp 10.0.16.9   port 443").desired_width(360.0));
                if !self.filter.is_empty() && ui.button("✖").clicked() { self.filter.clear(); }
                ui.checkbox(&mut self.follow, "Auto-scroll");
            });
            ui.add_space(4.0);
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&self.status).strong());
                if !self.source.is_empty() { ui.label(format!("— {}", self.source)); }
                ui.separator();
                let s = &self.stats;
                ui.label(format!("Packets {} | Bytes {} | Malformed {} | Truncated {} | Fragments {}", s.count, s.bytes, s.invalid, s.truncated, s.fragments));
                if s.count as usize > self.rows.len() { ui.label(RichText::new(format!("(table shows last {})", self.rows.len())).weak()); }
            });
            if let Some(e) = &self.error {
                ui.colored_label(Color32::from_rgb(240, 110, 110), format!("Error: {e}"));
            }
        });

        egui::Panel::right("summary").resizable(true).default_size(280.0).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("Protocols");
                let total = self.stats.count.max(1) as f32;
                let mut protocols: Vec<_> = self.stats.protocols.iter().collect();
                protocols.sort_by(|a, b| b.1.cmp(a.1));
                for (name, n) in protocols {
                    ui.horizontal(|ui| {
                        ui.colored_label(protocol_color(name), name);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.label(format!("{n}  ({:.0}%)", *n as f32 / total * 100.0)); });
                    });
                    ui.add(egui::ProgressBar::new(*n as f32 / total).desired_height(4.0));
                }
                if self.stats.invalid > 0 { ui.colored_label(protocol_color("Malformed"), format!("Malformed: {}", self.stats.invalid)); }
                ui.add_space(8.0);
                ui.heading("Top sources");
                let mut sources: Vec<_> = self.stats.sources.iter().collect();
                sources.sort_by(|a, b| b.1.cmp(a.1));
                for (ip, n) in sources.into_iter().take(10) {
                    ui.horizontal(|ui| {
                        if ui.link(ip).on_hover_text("Filter by this address").clicked() { self.filter = ip.clone(); }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.label(n.to_string()); });
                    });
                }
                ui.add_space(8.0);
                ui.heading("Packets per second");
                let points: PlotPoints = self.per_second.iter().enumerate().map(|(i, n)| [i as f64, *n as f64]).collect();
                Plot::new("rate").height(160.0).allow_drag(false).allow_zoom(false).allow_scroll(false).include_y(0.0)
                    .show(ui, |plot| plot.line(Line::new("packets/s", points)));
            });
        });

        if let Some(row) = self.selected.and_then(|i| self.row_by_index(i)) {
            let lines = row.info.verbose_lines().join("\n");
            let dump = hex_dump(&row.data);
            let truncated = row.info.truncated;
            egui::Panel::bottom("details").resizable(true).default_size(220.0).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Packet details");
                    if truncated { ui.colored_label(Color32::YELLOW, "capture truncated"); }
                });
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.label(RichText::new(lines).monospace());
                    ui.separator();
                    ui.label(RichText::new(dump).monospace());
                });
            });
        }

        egui::CentralPanel::default().show(ui, |ui| {
            let visible: Vec<usize> = (0..self.rows.len()).filter(|&i| matches(&self.filter, &self.rows[i])).collect();
            if self.rows.is_empty() {
                ui.centered_and_justified(|ui| ui.label(RichText::new(if busy { "Waiting for packets…

If nothing appears, this adapter may not carry your traffic: stop and pick another one." } else { "Choose an adapter and press Start capture, or open a .pcap file." }).weak()));
                return;
            }
            let mut clicked = None;
            let height = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .stick_to_bottom(self.follow)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(60.0).at_least(40.0))
                .column(Column::initial(80.0).at_least(50.0))
                .column(Column::initial(140.0).at_least(80.0))
                .column(Column::initial(140.0).at_least(80.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::initial(60.0).at_least(40.0))
                .column(Column::remainder())
                .header(height + 2.0, |mut header| {
                    for title in ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"] {
                        header.col(|ui| { ui.strong(title); });
                    }
                })
                .body(|body| {
                    body.rows(height, visible.len(), |mut table_row| {
                        let row = &self.rows[visible[table_row.index()]];
                        let info = &row.info;
                        table_row.set_selected(self.selected == Some(info.index));
                        let (src, dst) = match (info.addresses, info.link) {
                            (Some((s, d)), _) => (s.to_string(), d.to_string()),
                            (None, Some((s, d, _))) => (mac(&s), mac(&d)),
                            _ => (String::new(), String::new()),
                        };
                        let detail = match (&info.error, &info.detail) {
                            (Some(e), _) => format!("Parse error: {e}"),
                            (None, Some(d)) => d.clone(),
                            (None, None) => info.link.map(|(_, _, t)| format!("EtherType 0x{t:04X}")).unwrap_or_default(),
                        };
                        table_row.col(|ui| { ui.label(info.index.to_string()); });
                        table_row.col(|ui| { ui.label(format!("{:.3}", row.time)); });
                        table_row.col(|ui| { ui.label(src); });
                        table_row.col(|ui| { ui.label(dst); });
                        table_row.col(|ui| { ui.colored_label(protocol_color(&info.protocol), &info.protocol); });
                        table_row.col(|ui| { ui.label(info.original_len.to_string()); });
                        table_row.col(|ui| { ui.label(detail); });
                        if table_row.response().clicked() { clicked = Some(info.index); }
                    });
                });
            if let Some(i) = clicked {
                self.selected = if self.selected == Some(i) { None } else { Some(i) };
                self.follow = false;
            }
        });
    }

}

impl Drop for App {
    fn drop(&mut self) { self.stop(); }
}
