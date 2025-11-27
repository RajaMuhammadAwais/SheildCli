package proxy

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/shieldcli/shieldcli/pkg/config"
	"github.com/shieldcli/shieldcli/pkg/logging"
	"github.com/shieldcli/shieldcli/pkg/waf"
)

// Proxy represents the ShieldCLI reverse proxy with WAF
type Proxy struct {
	config       *config.Config
	logger       *logging.Logger
	wafEngine    *waf.Engine
	reverseProxy *httputil.ReverseProxy
	listener     net.Listener
	server       *http.Server
}

// NewProxy creates a new proxy instance
func NewProxy(cfg *config.Config, logger *logging.Logger) (*Proxy, error) {
	// Parse target URL
	targetURL, err := url.Parse(cfg.ProxyTo)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Create WAF engine
	wafEngine, err := waf.NewEngine(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF engine: %w", err)
	}

	// Create reverse proxy
	rp := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the reverse proxy
	rp.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-For", req.RemoteAddr)
		req.Header.Add("X-Forwarded-Proto", "http")
		req.Header.Add("X-Forwarded-Host", req.Header.Get("Host"))
	}

	// Add error handling
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}

	proxy := &Proxy{
		config:       cfg,
		logger:       logger,
		wafEngine:    wafEngine,
		reverseProxy: rp,
	}

	return proxy, nil
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	// Create HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.handleRequest(w, r)
	})

	// Create listener
	addr := fmt.Sprintf("0.0.0.0:%d", p.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.listener = listener

	// Create server
	p.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  time.Duration(p.config.Timeout) * time.Second,
		WriteTimeout: time.Duration(p.config.Timeout) * time.Second,
	}

	// Start server
	return p.server.Serve(listener)
}

// Stop stops the proxy server
func (p *Proxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

// handleRequest handles incoming HTTP requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Log incoming request
	p.logger.Debug("Incoming request: %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)

	// Intercept request body
	interceptor := &RequestInterceptor{}
	if err := interceptor.InterceptRequest(r); err != nil {
		p.logger.Error("Failed to intercept request: %v", err)
	}

	// Check WAF rules
	decision, reason := p.wafEngine.Check(r)

	if decision == waf.DecisionBlock {
		p.logger.Block("Request blocked: %s", reason)

		if p.config.Interactive {
			// In interactive mode, ask user
			if !p.askUser(reason) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden"))
				return
			}
		} else if !p.config.DryRun {
			// In normal mode, block the request
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}
		// In dry-run mode, log but continue
	}

	// Create a response writer wrapper to capture the response
	wrappedWriter := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	// Forward to target
	p.reverseProxy.ServeHTTP(wrappedWriter, r)

	// Log response
	p.logger.Debug("Response: %d %s", wrappedWriter.statusCode, http.StatusText(wrappedWriter.statusCode))
}

// askUser asks the user to approve or deny a request
func (p *Proxy) askUser(reason string) bool {
	fmt.Printf("\n[INTERACTIVE] Suspicious request detected: %s\n", reason)
	fmt.Print("[A]pprove or [D]eny? (a/d): ")

	var response string
	fmt.Scanln(&response)

	return response == "a" || response == "A"
}

// responseWriter wraps http.ResponseWriter to capture response data
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	written    bool
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write captures the response body
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}
