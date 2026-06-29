package sentinelmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const SDKVersion = "1.0.0"

type Options struct {
	APIKey     string
	BaseURL    string
	Timeout    time.Duration
	MaxRetries int
	Debug      bool
}

type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	maxRetries int
	debug      bool
	
	Events *EventsResource
}

func New(opts Options) *Client {
	if opts.APIKey == "" {
		panic("APIKey is required")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "https://api.sentinelmark.ai"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3
	}

	c := &Client{
		apiKey:     opts.APIKey,
		baseURL:    opts.BaseURL,
		httpClient: &http.Client{Timeout: opts.Timeout},
		maxRetries: opts.MaxRetries,
		debug:      opts.Debug,
	}

	c.Events = &EventsResource{client: c}
	return c
}

func (c *Client) request(ctx context.Context, method, path string, body interface{}, customHeaders map[string]string, v interface{}) error {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SentinelMark-SDK", "go")
	req.Header.Set("X-SentinelMark-Version", SDKVersion)
	req.Header.Set("User-Agent", "sentinelmark-go/"+SDKVersion)
	
	reqID := uuid.New().String()
	req.Header.Set("X-Request-Id", reqID)

	for k, val := range customHeaders {
		req.Header.Set(k, val)
	}

	retries := 0
	for {
		if c.debug {
			log.Printf("[SentinelMark] %s %s\n", method, url)
		}

		resp, err := c.httpClient.Do(req)

		if err != nil {
			if retries < c.maxRetries {
				retries++
				sleepTime := time.Duration(1<<retries) * 250 * time.Millisecond
				if c.debug {
					log.Printf("[SentinelMark] Network error: %v. Retrying in %v...\n", err, sleepTime)
				}
				time.Sleep(sleepTime)
				continue
			}
			return fmt.Errorf("network error: %w", err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			return json.NewDecoder(resp.Body).Decode(v)
		}

		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && retries < c.maxRetries {
			resp.Body.Close()
			retries++
			sleepTime := time.Duration(1<<retries) * 250 * time.Millisecond
			if c.debug {
				log.Printf("[SentinelMark] Request failed with %d. Retrying in %v...\n", resp.StatusCode, sleepTime)
			}
			time.Sleep(sleepTime)
			continue
		}

		return c.handleError(resp)
	}
}

func (c *Client) handleError(resp *http.Response) error {
	defer resp.Body.Close()

	var apiErr struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
		apiErr.ErrorCode = "UNKNOWN"
		apiErr.Message = "Unknown error"
	}

	base := &SentinelMarkError{
		ErrorCode: apiErr.ErrorCode,
		Message:   apiErr.Message,
		RequestID: apiErr.RequestID,
	}

	switch resp.StatusCode {
	case 401, 403:
		return &AuthError{base}
	case 400:
		return &ValidationError{base}
	case 429:
		return &RateLimitError{base}
	}
	if resp.StatusCode >= 500 {
		return &ApiError{base}
	}
	return base
}
