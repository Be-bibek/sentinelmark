use utoipa::OpenApi;
use crate::{
    adapters::models::{EventIngestRequest, ActionPolicy, DicomTracePayload, ProofTrace5GPayload, StellarFlowPayload},
    error::PlatformErrorResponse,
    response::ApiResponse,
    routes::events::EventResponse,
};

// Generic response schemas are tricky with utoipa macros, 
// so we typically declare the specific instantiated response envelopes manually or via macros.

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::events::handle_platform_event,
    ),
    components(
        schemas(
            EventIngestRequest,
            ActionPolicy,
            DicomTracePayload,
            ProofTrace5GPayload,
            StellarFlowPayload,
            PlatformErrorResponse,
            EventResponse,
            ApiResponse<EventResponse>
        )
    ),
    tags(
        (name = "SentinelMark Events", description = "Trust Engine public ingestion endpoints")
    )
)]
pub struct ApiDoc;
