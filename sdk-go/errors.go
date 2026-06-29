package sentinelmark

import "fmt"

type SentinelMarkError struct {
	ErrorCode string
	Message   string
	RequestID string
}

func (e *SentinelMarkError) Error() string {
	return fmt.Sprintf("[%s] %s (Request ID: %s)", e.ErrorCode, e.Message, e.RequestID)
}

type AuthError struct { *SentinelMarkError }
type ValidationError struct { *SentinelMarkError }
type RateLimitError struct { *SentinelMarkError }
type ApiError struct { *SentinelMarkError }
