package proxy

import (
	"bytes"
	"io"
	"net/http"
)

// RequestInterceptor intercepts and modifies HTTP requests
type RequestInterceptor struct {
	originalBody []byte
}

// InterceptRequest captures the request body for analysis
func (ri *RequestInterceptor) InterceptRequest(r *http.Request) error {
	if r.Body != nil && r.ContentLength > 0 {
		// Read the body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}

		// Store the original body
		ri.originalBody = body

		// Reset the body so it can be read again
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	return nil
}

// GetBody returns the intercepted request body
func (ri *RequestInterceptor) GetBody() []byte {
	return ri.originalBody
}

// ResponseInterceptor intercepts and modifies HTTP responses
type ResponseInterceptor struct {
	originalBody []byte
	statusCode   int
	headers      http.Header
}

// InterceptResponse captures the response for analysis
func (rsi *ResponseInterceptor) InterceptResponse(w http.ResponseWriter, statusCode int, body []byte) {
	rsi.statusCode = statusCode
	rsi.originalBody = body
	rsi.headers = w.Header().Clone()
}

// GetBody returns the intercepted response body
func (rsi *ResponseInterceptor) GetBody() []byte {
	return rsi.originalBody
}

// GetStatusCode returns the response status code
func (rsi *ResponseInterceptor) GetStatusCode() int {
	return rsi.statusCode
}

// GetHeaders returns the response headers
func (rsi *ResponseInterceptor) GetHeaders() http.Header {
	return rsi.headers
}
