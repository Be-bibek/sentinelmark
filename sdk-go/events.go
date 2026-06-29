package sentinelmark

import (
	"context"
	"time"
)

type EvaluateOptions struct {
	ProductSlug    string
	EventType      string
	Payload        map[string]interface{}
	Metadata       map[string]interface{}
	IdempotencyKey string
}

type internalEventRequest struct {
	ProductSlug     string                 `json:"product_slug"`
	APIVersion      string                 `json:"api_version"`
	ProtocolVersion string                 `json:"protocol_version"`
	SDKVersion      string                 `json:"sdk_version"`
	EventType       string                 `json:"event_type"`
	Timestamp       string                 `json:"timestamp"`
	Payload         map[string]interface{} `json:"payload"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type EventResponse struct {
	EventID    string  `json:"event_id"`
	Decision   string  `json:"decision"`
	RiskScore  float64 `json:"risk_score"`
	TrustScore float64 `json:"trust_score"`
	Message    string  `json:"message"`
}

type ApiResponse struct {
	Success       bool          `json:"success"`
	RequestID     string        `json:"request_id"`
	Timestamp     string        `json:"timestamp"`
	EngineVersion string        `json:"engine_version"`
	APIVersion    string        `json:"api_version"`
	LatencyMs     int64         `json:"latency_ms,omitempty"`
	Data          EventResponse `json:"data"`
}

type EventsResource struct {
	client *Client
}

func (r *EventsResource) Evaluate(ctx context.Context, opts EvaluateOptions) (*ApiResponse, error) {
	headers := make(map[string]string)
	if opts.IdempotencyKey != "" {
		headers["Idempotency-Key"] = opts.IdempotencyKey
	}

	if opts.Metadata == nil {
		opts.Metadata = make(map[string]interface{})
	}

	req := internalEventRequest{
		ProductSlug:     opts.ProductSlug,
		APIVersion:      "v1",
		ProtocolVersion: "1.0",
		SDKVersion:      SDKVersion,
		EventType:       opts.EventType,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Payload:         opts.Payload,
		Metadata:        opts.Metadata,
	}

	var res ApiResponse
	err := r.client.request(ctx, "POST", "/api/v1/events", req, headers, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
