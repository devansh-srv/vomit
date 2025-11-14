use anyhow::{Context, Result};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use nonzero_ext::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::llm::prompt;

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}
#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}
#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}
#[derive(Deserialize)]
struct MessageContent {
    content: String,
}

pub struct LLMClient {
    client: Client,
    api_token: String,
    model: String,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}
impl LLMClient {
    pub fn new(api_token: String) -> Self {
        let quota = Quota::per_minute(nonzero!(10u32));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        Self {
            client: Client::new(),
            api_token,
            model: "openai/gpt-oss-20b:groq".to_string(),
            rate_limiter,
        }
    }
    pub async fn analyze(&self, prompt: String) -> Result<String> {
        self.rate_limiter.until_ready().await;
        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role:"system".to_string(),
                content:"You are a Linux performance analysis expert. Analyze system metrics and provide concise, actionable insights.".to_string(),
            }, Message {
                    role:"user".to_string(),
                    content:prompt,
                }],
            max_tokens: 800,
            temperature: 0.7,
        };
        // API_URL = "https://router.huggingface.co/v1/chat/completions"
        let url = "https://router.huggingface.co/v1/chat/completions";
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&request)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .context("Failed to send request to HuggingFace")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("API request failed ({}): {}", status, body);
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse HuggingFace response")?;

        let analysis = chat_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_else(|| "No analysis generated".to_string());

        Ok(analysis)
    }
}
