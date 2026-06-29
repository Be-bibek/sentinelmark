import time
import uuid
import logging
import requests
from typing import Dict, Any, Optional

from .errors import (
    SentinelMarkAuthError,
    SentinelMarkValidationError,
    SentinelMarkRateLimitError,
    SentinelMarkApiError,
    SentinelMarkError,
)

logger = logging.getLogger("sentinelmark")

class EventsResource:
    def __init__(self, client):
        self._client = client

    def evaluate(self, product_slug: str, event_type: str, payload: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Evaluates an event through the Trust Engine."""
        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
            
        body = {
            "product_slug": product_slug,
            "api_version": "v1",
            "protocol_version": "1.0",
            "sdk_version": self._client.sdk_version,
            "event_type": event_type,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "payload": payload,
            "metadata": metadata or {}
        }
        return self._client._request("POST", "/api/v1/events", json=body, headers=headers)

class SentinelMark:
    """Official Python Client for the SentinelMark Platform."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.sentinelmark.ai",
        timeout: int = 30,
        max_retries: int = 3,
        debug: bool = False,
    ):
        if not api_key:
            raise ValueError("api_key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.sdk_version = "1.0.0"

        if debug:
            logging.basicConfig(level=logging.DEBUG)
            logger.setLevel(logging.DEBUG)

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-SentinelMark-SDK": "python",
            "X-SentinelMark-Version": self.sdk_version,
            "User-Agent": f"sentinelmark-python/{self.sdk_version}",
        })

        # Register Resources
        self.events = EventsResource(self)

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        
        headers = kwargs.pop("headers", {})
        if "X-Request-Id" not in headers:
            headers["X-Request-Id"] = str(uuid.uuid4())

        kwargs["headers"] = headers
        kwargs["timeout"] = self.timeout

        retries = 0
        while True:
            try:
                logger.debug(f"Request: {method} {url} | Headers: {headers}")
                response = self.session.request(method, url, **kwargs)
                
                # Success
                if 200 <= response.status_code < 300:
                    return response.json()
                
                # Retryable Errors
                if response.status_code in (429, 500, 502, 503, 504) and retries < self.max_retries:
                    retries += 1
                    sleep_time = (2 ** retries) * 0.25 # Exponential backoff
                    logger.warning(f"Request failed with {response.status_code}. Retrying in {sleep_time}s...")
                    time.sleep(sleep_time)
                    continue
                
                self._handle_error(response)
                
            except requests.exceptions.RequestException as e:
                if retries < self.max_retries:
                    retries += 1
                    sleep_time = (2 ** retries) * 0.25
                    logger.warning(f"Request exception: {e}. Retrying in {sleep_time}s...")
                    time.sleep(sleep_time)
                    continue
                raise SentinelMarkError(f"Network error: {str(e)}")

    def _handle_error(self, response: requests.Response):
        try:
            data = response.json()
            error_code = data.get("error_code", "UNKNOWN")
            message = data.get("message", "Unknown error")
            request_id = data.get("request_id", "")
        except Exception:
            error_code = "UNKNOWN"
            message = response.text
            request_id = ""

        if response.status_code in (401, 403):
            raise SentinelMarkAuthError(message, error_code, request_id)
        elif response.status_code == 400:
            raise SentinelMarkValidationError(message, error_code, request_id)
        elif response.status_code == 429:
            raise SentinelMarkRateLimitError(message, error_code, request_id)
        elif response.status_code >= 500:
            raise SentinelMarkApiError(message, error_code, request_id)
        else:
            raise SentinelMarkError(message, error_code, request_id)
