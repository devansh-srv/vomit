use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct Analysis {
    pub timestamp: u64,
    pub summary: String,
    pub bottlenecks: Vec<String>,
    pub recommendations: Vec<String>,
}

impl Analysis {
    pub fn new(text: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Parse LLM response
        let (summary, bottlenecks, recommendations) = Self::parse_response(&text);

        Self {
            timestamp,
            summary,
            bottlenecks,
            recommendations,
        }
    }

    fn parse_response(text: &str) -> (String, Vec<String>, Vec<String>) {
        let mut summary = String::new();
        let mut bottlenecks = Vec::new();
        let mut recommendations = Vec::new();

        let mut current_section = "";

        for line in text.lines() {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            // Detect sections
            if line.to_lowercase().contains("summary") {
                current_section = "summary";
                continue;
            } else if line.to_lowercase().contains("root cause")
                || line.to_lowercase().contains("bottleneck")
                || line.to_lowercase().contains("issue")
            {
                current_section = "bottlenecks";
                continue;
            } else if line.to_lowercase().contains("recommendation")
                || line.to_lowercase().contains("fix")
                || line.to_lowercase().contains("solution")
            {
                current_section = "recommendations";
                continue;
            }

            // Add to appropriate section
            match current_section {
                "summary" => {
                    if !summary.is_empty() {
                        summary.push(' ');
                    }
                    summary.push_str(line);
                }
                "bottlenecks" => {
                    if line.starts_with('-') || line.starts_with('•') || line.starts_with('*') {
                        bottlenecks
                            .push(line.trim_start_matches(&['-', '•', '*', ' ']).to_string());
                    } else if !line.is_empty() {
                        bottlenecks.push(line.to_string());
                    }
                }
                "recommendations" => {
                    if line.starts_with('-') || line.starts_with('•') || line.starts_with('*') {
                        recommendations
                            .push(line.trim_start_matches(&['-', '•', '*', ' ']).to_string());
                    } else if !line.is_empty() {
                        recommendations.push(line.to_string());
                    }
                }
                _ => {
                    // Default to summary if no section detected
                    if !summary.is_empty() {
                        summary.push(' ');
                    }
                    summary.push_str(line);
                }
            }
        }

        // Fallback if parsing fails
        if summary.is_empty() {
            summary = text.lines().take(3).collect::<Vec<_>>().join(" ");
        }

        (summary, bottlenecks, recommendations)
    }

    pub fn format_time(&self) -> String {
        use chrono::{DateTime, Utc};
        let dt = DateTime::<Utc>::from_timestamp(self.timestamp as i64, 0).unwrap();
        dt.format("%H:%M:%S").to_string()
    }
}
