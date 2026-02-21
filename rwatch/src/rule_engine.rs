use log::info;
use rwatch_common::{ExecEvent, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RuleType {
    SuspiciousPathPrefix(String),
    SuspiciousCommand(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub rule_type: RuleType,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Serialize)]
pub struct Alert {
    pub rule: Rule,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub filename: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RulesConfig {
    pub rules: Vec<Rule>,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let content = fs::read_to_string(path)?;
        let config: RulesConfig = serde_yaml::from_str(&content)?;
        self.rules = config.rules;
        info!("Loaded {} rules from configuration", self.rules.len());
        Ok(())
    }

    pub fn load_defaults(&mut self) {
        self.rules = vec![
            Rule {
                rule_type: RuleType::SuspiciousPathPrefix("/tmp".to_string()),
                description: "Execution from /tmp is suspicious".to_string(),
                severity: Severity::Warning,
            },
            Rule {
                rule_type: RuleType::SuspiciousCommand("/usr/bin/nmap".to_string()),
                description: "Port scanning tool detected".to_string(),
                severity: Severity::Critical,
            },
        ];
    }

    pub fn evaluate(&self, event: &ExecEvent) -> Vec<Alert> {
        let filename_str = String::from_utf8_lossy(&event.filename)
            .trim_end_matches('\0')
            .to_string();

        let comm_str = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();

        self.rules
            .iter()
            .filter_map(|rule| match &rule.rule_type {
                RuleType::SuspiciousPathPrefix(prefix) => {
                    if filename_str.starts_with(prefix) {
                        Some(Alert {
                            rule: rule.clone(),
                            pid: event.pid,
                            uid: event.uid,
                            comm: comm_str.clone(),
                            filename: filename_str.clone(),
                        })
                    } else {
                        None
                    }
                }
                RuleType::SuspiciousCommand(cmd) => {
                    if filename_str == *cmd {
                        Some(Alert {
                            rule: rule.clone(),
                            pid: event.pid,
                            uid: event.uid,
                            comm: comm_str.clone(),
                            filename: filename_str.clone(),
                        })
                    } else {
                        None
                    }
                }
            })
            .collect()
    }
}
