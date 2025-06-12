use log::info;
use rwatch_common::ExecEvent;

#[derive(Debug, Clone)]
pub enum RuleType {
    SuspiciousPathPrefix(String),
    SuspiciousCommand(String),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_type: RuleType,
    pub description: String,
}

#[derive(Debug)]
pub struct Alert {
    pub rule: Rule,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Rule {
                    rule_type: RuleType::SuspiciousPathPrefix("/tmp".to_string()),
                    description: "Execution from /tmp is suspicious".to_string(),
                },
                Rule {
                    rule_type: RuleType::SuspiciousCommand("nmap".to_string()),
                    description: "Port scanning tool detected".to_string(),
                },
            ],
        }
    }

    pub fn evaluate(&self, event: &ExecEvent) -> Vec<Alert> {
        let comm_str = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();

        info!("received command: {}", comm_str);
        self.rules
            .iter()
            .filter_map(|rule| {
                match &rule.rule_type {
                    RuleType::SuspiciousPathPrefix(prefix) => {
                        if comm_str.starts_with(prefix) {
                            Some(Alert {
                                rule: rule.clone(),
                                pid: event.pid,
                                uid: event.uid,
                                comm: comm_str.clone(),
                            })
                        } else {
                            None
                        }
                    }
                    RuleType::SuspiciousCommand(cmd) => {
                        if comm_str == *cmd {
                            Some(Alert {
                                rule: rule.clone(),
                                pid: event.pid,
                                uid: event.uid,
                                comm: comm_str.clone(),
                            })
                        } else {
                            None
                        }
                    }
                }
            })
            .collect()
    }

}
