use eframe::{egui, epi};
use std::fs;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use std::io::Write;

const NET_RULE_PATH: &str = "net_rule.csv";
const FIREWALL_PATH: &str = "/dev/firewall_ctrl";
const LOG_PATH: &str = "/proc/fw_log";
const CONNECTION_TABLE_PATH: &str = "/proc/connection_table";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rule {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flow_direction: u8,
    action: u8,
    log: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Connection {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: String, // 修改为 String 类型
    state: u8,
    last_seen: String,
}

struct MyApp {
    current_tab: Tab,
    log_content: String,
    rules: Vec<Rule>,
    connections: Vec<Connection>,
    last_update: Instant,
}

#[derive(Clone, Copy)]
enum Tab {
    Firewall,
    Rules,
    ConnectionTable,
}

impl Default for MyApp {
    fn default() -> Self {
        let log_content = fs::read_to_string(LOG_PATH).unwrap_or_default();
        let rules = read_rules_from_csv(NET_RULE_PATH).unwrap_or_default();
        let connections = read_connections_from_csv(CONNECTION_TABLE_PATH).unwrap_or_default();
        if connections.is_empty() {
            println!("Empty");
        }
        Self {
            current_tab: Tab::Firewall,
            log_content,
            rules,
            connections,
            last_update: Instant::now(),
        }
    }
}

impl epi::App for MyApp {
    fn name(&self) -> &str {
        "Firewall Management"
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &epi::Frame) {
        if self.last_update.elapsed() >= Duration::from_secs(1) {
            self.connections = read_connections_from_csv(CONNECTION_TABLE_PATH).unwrap_or_default();
            self.last_update = Instant::now();
            self.log_content = fs::read_to_string(LOG_PATH).unwrap_or_default();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Firewall").clicked() {
                    self.current_tab = Tab::Firewall;
                }
                if ui.button("Rules").clicked() {
                    self.current_tab = Tab::Rules;
                }
                if ui.button("Connection Table").clicked() {
                    self.current_tab = Tab::ConnectionTable;
                }
            });

            match self.current_tab {
                Tab::Firewall => self.firewall_ui(ui),
                Tab::Rules => self.rules_ui(ui),
                Tab::ConnectionTable => self.connection_table_ui(ui),
            }
        });
    }
}

impl MyApp {
    fn firewall_ui(&mut self, ui: &mut egui::Ui) {
        if ui.button("Toggle Firewall").clicked() {
            let _ = std::fs::write(FIREWALL_PATH, "toggle");
        }

        ui.label("Logs:");
        ui.horizontal(|ui| {
            ui.label(&self.log_content);
        });
    }

    fn rules_ui(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("rules_grid")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Source IP");
                    ui.label("Destination IP");
                    ui.label("Source Port");
                    ui.label("Destination Port");
                    ui.label("Protocol");
                    ui.label("Flow Direction");
                    ui.label("Action");
                    ui.label("Log");
                    ui.label("Actions");
                    ui.end_row();

                    let mut indices_to_remove = Vec::new();

                    for (index, rule) in self.rules.iter_mut().enumerate() {
                        ui.text_edit_singleline(&mut rule.src_ip);
                        ui.text_edit_singleline(&mut rule.dst_ip);
                        ui.add(egui::DragValue::new(&mut rule.src_port));
                        ui.add(egui::DragValue::new(&mut rule.dst_port));
                        ui.add(egui::DragValue::new(&mut rule.protocol));
                        ui.add(egui::DragValue::new(&mut rule.flow_direction));
                        ui.add(egui::DragValue::new(&mut rule.action));
                        ui.add(egui::DragValue::new(&mut rule.log));

                        if ui.button("Delete").clicked() {
                            indices_to_remove.push(index);
                        }
                        ui.end_row();
                    }

                    for index in indices_to_remove.iter().rev() {
                        self.rules.remove(*index);
                    }

                    if ui.button("Add Rule").clicked() {
                        self.rules.push(Rule {
                            src_ip: String::new(),
                            dst_ip: String::new(),
                            src_port: 0,
                            dst_port: 0,
                            protocol: 0,
                            flow_direction: 0,
                            action: 0,
                            log: 0,
                        });
                    }
                });
        });

        if ui.button("Save Rules").clicked() {
            if let Err(err) = save_rules_to_csv(NET_RULE_PATH, &self.rules) {
                ui.label(format!("Failed to save rules: {}", err));
            }
            write_fw_ctrl("2").unwrap();
        }
    }

    fn connection_table_ui(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("connection_table_grid")
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Source IP");
                    ui.label("Destination IP");
                    ui.label("Source Port");
                    ui.label("Destination Port");
                    ui.label("Protocol");
                    ui.label("State");
                    ui.label("Last Seen");
                    ui.end_row();

                    for connection in &self.connections {
                        ui.label(&connection.src_ip);
                        ui.label(&connection.dst_ip);
                        ui.label(connection.src_port.to_string());
                        ui.label(connection.dst_port.to_string());
                        ui.label(&connection.proto); // 显示协议名字
                        ui.label(connection.state.to_string());
                        ui.label(&connection.last_seen);
                        ui.end_row();
                    }
                });
        });
    }
}

fn read_rules_from_csv(path: &str) -> Result<Vec<Rule>, csv::Error> {
    let mut rdr = csv::Reader::from_path(path)?;
    let mut rules = Vec::new();
    for result in rdr.deserialize() {
        let rule: Rule = result?;
        rules.push(rule);
    }
    Ok(rules)
}

fn save_rules_to_csv(path: &str, rules: &[Rule]) -> Result<(), csv::Error> {
    let mut wtr = csv::Writer::from_path(path)?;
    for rule in rules {
        wtr.serialize(rule)?;
    }
    wtr.flush()?;
    Ok(())
}

fn read_connections_from_csv(path: &str) -> Result<Vec<Connection>, csv::Error> {
    let mut rdr = csv::Reader::from_path(path)?;
    let mut connections = Vec::new();
    for result in rdr.deserialize() {
        match result {
            Ok(connection) => connections.push(connection),
            Err(e) => eprintln!("Failed to deserialize connection: {}", e),
        }
    }
    Ok(connections)
}

fn write_fw_ctrl(value: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(FIREWALL_PATH)?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

fn main() {
    let options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(MyApp::default()), options);
}