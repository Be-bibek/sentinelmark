use crate::{
    adapters::models::{
        ActionPolicy, DicomTracePayload, EventIngestRequest, ProofTrace5GPayload,
        StellarFlowPayload,
    },
    error::PlatformErrorResponse,
    response::ApiResponse,
    routes::events::EventResponse,
};
use utoipa::OpenApi;

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
