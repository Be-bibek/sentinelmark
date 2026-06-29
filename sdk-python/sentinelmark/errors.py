class SentinelMarkError(Exception):
    """Base exception for all SentinelMark errors."""
    def __init__(self, message: str, error_code: str = None, request_id: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.request_id = request_id

    def __str__(self):
        return f"[{self.error_code}] {self.message} (Request ID: {self.request_id})"

class SentinelMarkAuthError(SentinelMarkError):
    """Raised for 401 or 403 authorization errors."""
    pass

class SentinelMarkValidationError(SentinelMarkError):
    """Raised for 400 validation errors."""
    pass

class SentinelMarkRateLimitError(SentinelMarkError):
    """Raised for 429 rate limit errors."""
    pass

class SentinelMarkApiError(SentinelMarkError):
    """Raised for 500+ internal server errors."""
    pass
