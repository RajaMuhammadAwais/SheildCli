package waf

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/shieldcli/shieldcli/pkg/config"
	"github.com/shieldcli/shieldcli/pkg/logging"
)

// Decision represents the WAF decision
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionBlock
	DecisionLog
)

// Engine represents the custom WAF engine
type Engine struct {
	config *config.Config
	logger *logging.Logger
	rules  []*Rule
}

// NewEngine creates a new WAF engine
func NewEngine(cfg *config.Config, logger *logging.Logger) (*Engine, error) {
	engine := &Engine{
		config: cfg,
		logger: logger,
		rules:  make([]*Rule, 0),
	}

	// Add default OWASP-style rules
	engine.addDefaultRules()

	return engine, nil
}

// addDefaultRules adds a set of default security rules
func (e *Engine) addDefaultRules() {
	defaultRules := []*Rule{
		// SQL Injection detection
		{
			ID:          1001,
			Name:        "SQL Injection - Common Patterns",
			Description: "Detects common SQL injection patterns",
			Phase:       PhaseRequestBody,
			Operator:    OpSQLi,
			Target:      "REQUEST_BODY",
			Action:      ActionBlock,
			Severity:    "critical",
			Enabled:     true,
		},
		// XSS detection
		{
			ID:          1002,
			Name:        "Cross-Site Scripting (XSS)",
			Description: "Detects common XSS patterns",
			Phase:       PhaseRequestBody,
			Operator:    OpXSS,
			Target:      "REQUEST_BODY",
			Action:      ActionBlock,
			Severity:    "critical",
			Enabled:     true,
		},
		// Path traversal detection
			{
				ID:          1003,
				Name:        "Path Traversal",
				Description: "Detects path traversal attempts",
				Phase:       PhaseRequestURI,
				Operator:    OpRegex,
				Pattern:     `\.\.[/\\]|\.\..%2[fF]`,
				Target:      "REQUEST_URI",
				Action:      ActionBlock,
				Severity:    "high",
				Enabled:     true,
			},
		// Command injection detection
			{
				ID:          1004,
				Name:        "Command Injection",
				Description: "Detects command injection patterns",
				Phase:       PhaseRequestBody,
				Operator:    OpRegex,
				Pattern:     `[;&|\n][\s]*(cat|ls|rm|wget|curl|bash|sh|cmd|powershell)`,
				Target:      "REQUEST_BODY",
				Action:      ActionBlock,
				Severity:    "critical",
				Enabled:     true,
			},
		// Bad User-Agent
		{
			ID:          1005,
			Name:        "Suspicious User-Agent",
			Description: "Blocks requests from suspicious user agents",
			Phase:       PhaseRequestHeaders,
			Operator:    OpContains,
			Pattern:     "BadBot",
			Target:      "REQUEST_HEADERS:User-Agent",
			Action:      ActionBlock,
			Severity:    "medium",
			Enabled:     true,
		},
		// High entropy payload detection
		{
			ID:          1006,
			Name:        "High Entropy Payload",
			Description: "Detects high entropy payloads (potential encoding/obfuscation)",
			Phase:       PhaseRequestBody,
			Operator:    OpHighEntropy,
			Target:      "REQUEST_BODY",
			Action:      ActionLog,
			Severity:    "medium",
			Enabled:     true,
		},
	}

	for _, rule := range defaultRules {
		if err := rule.Compile(); err != nil {
			e.logger.Warn("Failed to compile rule %d: %v", rule.ID, err)
		} else {
			e.rules = append(e.rules, rule)
		}
	}

	e.logger.Debug("Loaded %d default WAF rules", len(e.rules))
}

// AddRule adds a custom rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	if err := rule.Compile(); err != nil {
		return fmt.Errorf("failed to compile rule: %w", err)
	}
	e.rules = append(e.rules, rule)
	e.logger.Debug("Added custom rule: %s (ID: %d)", rule.Name, rule.ID)
	return nil
}

// Check checks an HTTP request against all WAF rules
func (e *Engine) Check(r *http.Request) (Decision, string) {
	// Check request headers phase rules
	for _, rule := range e.rules {
		if rule.Phase != PhaseRequestHeaders {
			continue
		}

		if e.checkRule(rule, r) {
			if rule.Action == ActionBlock {
				return DecisionBlock, fmt.Sprintf("Rule %d: %s", rule.ID, rule.Name)
			}
		}
	}

	// Check request URI phase rules
	for _, rule := range e.rules {
		if rule.Phase != PhaseRequestURI {
			continue
		}

		if e.checkRule(rule, r) {
			if rule.Action == ActionBlock {
				return DecisionBlock, fmt.Sprintf("Rule %d: %s", rule.ID, rule.Name)
			}
		}
	}

	// Check request body phase rules
	for _, rule := range e.rules {
		if rule.Phase != PhaseRequestBody {
			continue
		}

		if e.checkRule(rule, r) {
			if rule.Action == ActionBlock {
				return DecisionBlock, fmt.Sprintf("Rule %d: %s", rule.ID, rule.Name)
			}
		}
	}

	return DecisionAllow, ""
}

// checkRule checks if a rule matches the request
func (e *Engine) checkRule(rule *Rule, r *http.Request) bool {
	if !rule.Enabled {
		return false
	}

	var data string

	// Extract data based on target
	switch {
	case rule.Target == "REQUEST_URI":
		data = r.RequestURI
	case rule.Target == "REQUEST_BODY":
		// For now, we'll skip body checking in this phase
		// This will be enhanced later
		return false
	case strings.HasPrefix(rule.Target, "REQUEST_HEADERS:"):
		headerName := strings.TrimPrefix(rule.Target, "REQUEST_HEADERS:")
		data = r.Header.Get(headerName)
	case rule.Target == "REQUEST_HEADERS":
		// Check all headers
		for name, values := range r.Header {
			for _, value := range values {
				if rule.Match(value) {
					e.logger.Debug("Rule %d matched in header %s", rule.ID, name)
					return true
				}
			}
		}
		return false
	case rule.Target == "ARGS":
		// Check query parameters
		for key, values := range r.URL.Query() {
			for _, value := range values {
				if rule.Match(value) {
					e.logger.Debug("Rule %d matched in argument %s", rule.ID, key)
					return true
				}
			}
		}
		return false
	default:
		return false
	}

	if data != "" && rule.Match(data) {
		e.logger.Debug("Rule %d matched: %s", rule.ID, rule.Name)
		return true
	}

	return false
}

// GetRules returns all rules in the engine
func (e *Engine) GetRules() []*Rule {
	return e.rules
}
