use log::{error, info, warn};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct WebhookNotifier {
    client: Client,
    url: String,
}

impl WebhookNotifier {
    pub fn new(url: String) -> Option<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;
        info!("Webhook alerting enabled → {}", url);
        Some(Self { client, url })
    }

    pub fn send(&self, payload: Value) {
        let client = self.client.clone();
        let url = self.url.clone();

        tokio::spawn(async move {
            match client.post(&url).json(&payload).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!(
                            "Webhook returned non-success status: {} for URL: {}",
                            resp.status(),
                            url
                        );
                    }
                }
                Err(e) => {
                    error!("Webhook send failed ({}): {}", url, e);
                }
            }
        });
    }

    pub fn format_alert(
        severity: &str,
        alert_type: &str,
        description: &str,
        pid: u32,
        uid: u32,
        comm: &str,
        extra_fields: &[(&str, &str)],
    ) -> Value {
        let emoji = match severity {
            "critical" => "🚨",
            "warning" => "⚠️",
            _ => "ℹ️",
        };

        let mut text = format!(
            "{} *[{}]* {}\nPID: {} | UID: {} | Comm: {}",
            emoji,
            severity.to_uppercase(),
            description,
            pid,
            uid,
            comm,
        );

        for (key, value) in extra_fields {
            text.push_str(&format!("\n{}: {}", key, value));
        }

        serde_json::json!({
            "text": text,
            "alert_type": alert_type,
            "severity": severity,
            "pid": pid,
            "uid": uid,
            "comm": comm,
        })
    }
}
