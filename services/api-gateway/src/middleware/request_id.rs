//! X-Request-ID middleware.
//! Every request gets a unique ID injected into headers and tracing spans.

use tower_http::request_id::{MakeRequestId, RequestId};
use uuid::Uuid;

#[derive(Clone)]
pub struct MakeUuidRequestId;

impl MakeRequestId for MakeUuidRequestId {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        let id = Uuid::new_v4().to_string();
        let header_val = axum::http::HeaderValue::from_str(&id).ok()?;
        Some(RequestId::new(header_val))
    }
}
