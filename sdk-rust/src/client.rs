use chrono::Utc;
use reqwest::{
    Client as ReqwestClient,
    header::{HeaderMap, HeaderValue},
};
use std::time::Duration;
use uuid::Uuid;

use crate::error::SentinelMarkError;
use crate::models::{ApiResponse, ErrorBody, EvaluateOptions, EventResponse, InternalEventRequest};

const SDK_VERSION: &str = "1.0.0";

pub struct SentinelMark {
    client: ReqwestClient,
    base_url: String,
    max_retries: u32,
    debug: bool,
    pub events: EventsResource,
}

impl SentinelMark {
    pub fn new(api_key: &str) -> Self {
        Self::builder(api_key).build().unwrap()
    }

    pub fn builder(api_key: &str) -> SentinelMarkBuilder {
        SentinelMarkBuilder::new(api_key)
    }

    pub(crate) async fn request<T, R>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&T>,
        custom_headers: Option<HeaderMap>,
    ) -> Result<R, SentinelMarkError>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut retries = 0;

        loop {
            let mut req = self.client.request(method.clone(), &url);

            let mut headers = HeaderMap::new();
            headers.insert(
                "X-Request-Id",
                HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
            );
            if let Some(ref ch) = custom_headers {
                for (k, v) in ch.iter() {
                    headers.insert(k.clone(), v.clone());
                }
            }
            req = req.headers(headers);

            if let Some(b) = body {
                req = req.json(b);
            }

            if self.debug {
                println!("[SentinelMark] Request: {} {}", method, url);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let data = resp.json::<R>().await?;
                        return Ok(data);
                    }

                    if (status.as_u16() == 429 || status.is_server_error())
                        && retries < self.max_retries
                    {
                        retries += 1;
                        let sleep_time = 2u64.pow(retries) * 250;
                        if self.debug {
                            println!(
                                "[SentinelMark] Request failed with {}. Retrying in {}ms...",
                                status, sleep_time
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(sleep_time)).await;
                        continue;
                    }

                    return Err(Self::handle_error(resp).await);
                }
                Err(e) => {
                    if retries < self.max_retries {
                        retries += 1;
                        let sleep_time = 2u64.pow(retries) * 250;
                        if self.debug {
                            println!(
                                "[SentinelMark] Network error: {}. Retrying in {}ms...",
                                e, sleep_time
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(sleep_time)).await;
                        continue;
                    }
                    return Err(SentinelMarkError::Network(e));
                }
            }
        }
    }

    async fn handle_error(resp: reqwest::Response) -> SentinelMarkError {
        let status = resp.status();
        let error_body: Result<ErrorBody, _> = resp.json().await;

        let (code, msg, req_id) = match error_body {
            Ok(b) => (b.error_code, b.message, b.request_id),
            Err(_) => (
                "UNKNOWN".to_string(),
                "Unknown error".to_string(),
                "".to_string(),
            ),
        };

        match status.as_u16() {
            401 | 403 => SentinelMarkError::Auth {
                error_code: code,
                message: msg,
                request_id: req_id,
            },
            400 => SentinelMarkError::Validation {
                error_code: code,
                message: msg,
                request_id: req_id,
            },
            429 => SentinelMarkError::RateLimit {
                error_code: code,
                message: msg,
                request_id: req_id,
            },
            500..=599 => SentinelMarkError::Api {
                error_code: code,
                message: msg,
                request_id: req_id,
            },
            _ => SentinelMarkError::Unknown(msg),
        }
    }
}

pub struct SentinelMarkBuilder {
    api_key: String,
    base_url: String,
    timeout: u64,
    max_retries: u32,
    debug: bool,
}

impl SentinelMarkBuilder {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            base_url: "https://api.sentinelmark.ai".to_string(),
            timeout: 30,
            max_retries: 3,
            debug: false,
        }
    }

    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    pub fn debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub fn build(self) -> Result<SentinelMark, SentinelMarkError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.api_key)).unwrap(),
        );
        headers.insert("X-SentinelMark-SDK", HeaderValue::from_static("rust"));
        headers.insert(
            "X-SentinelMark-Version",
            HeaderValue::from_static(SDK_VERSION),
        );
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&format!("sentinelmark-rust/{}", SDK_VERSION)).unwrap(),
        );

        let client = ReqwestClient::builder()
            .timeout(Duration::from_secs(self.timeout))
            .default_headers(headers)
            .build()?;

        let sm = SentinelMark {
            client,
            base_url: self.base_url,
            max_retries: self.max_retries,
            debug: self.debug,
            events: EventsResource,
        };

        Ok(sm)
    }
}

pub struct EventsResource;

impl EventsResource {
    pub async fn evaluate(
        &self,
        client: &SentinelMark,
        options: EvaluateOptions,
    ) -> Result<ApiResponse<EventResponse>, SentinelMarkError> {
        let mut headers = HeaderMap::new();
        if let Some(idem) = options.idempotency_key {
            headers.insert("Idempotency-Key", HeaderValue::from_str(&idem).unwrap());
        }

        let body = InternalEventRequest {
            product_slug: options.product_slug,
            api_version: "v1".to_string(),
            protocol_version: "1.0".to_string(),
            sdk_version: SDK_VERSION.to_string(),
            event_type: options.event_type,
            timestamp: Utc::now().to_rfc3339(),
            payload: options.payload,
            metadata: options.metadata.unwrap_or_else(|| serde_json::json!({})),
        };

        client
            .request(
                reqwest::Method::POST,
                "/api/v1/events",
                Some(&body),
                Some(headers),
            )
            .await
    }
}
