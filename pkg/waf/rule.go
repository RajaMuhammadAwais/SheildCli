package waf

import (
	"math"
	"regexp"
	"strings"
)

// RuleAction defines the action to take when a rule matches
type RuleAction string

const (
	ActionBlock RuleAction = "block"
	ActionLog   RuleAction = "log"
	ActionPass  RuleAction = "pass"
)

// RulePhase defines the phase in which a rule is evaluated
type RulePhase string

const (
	PhaseRequestHeaders  RulePhase = "request_headers"
	PhaseRequestURI      RulePhase = "request_uri"
	PhaseRequestBody     RulePhase = "request_body"
	PhaseResponseHeaders RulePhase = "response_headers"
	PhaseResponseBody    RulePhase = "response_body"
)

// RuleOperator defines the type of matching operation
type RuleOperator string

const (
	OpContains    RuleOperator = "contains"
	OpRegex       RuleOperator = "regex"
	OpStartsWith  RuleOperator = "startswith"
	OpEndsWith    RuleOperator = "endswith"
	OpEquals      RuleOperator = "equals"
	OpNotContains RuleOperator = "notcontains"
	OpNotRegex    RuleOperator = "notregex"
	OpHighEntropy RuleOperator = "high_entropy"
	OpSQLi        RuleOperator = "sqli"
	OpXSS         RuleOperator = "xss"
)

// Rule represents a single WAF rule
type Rule struct {
	ID          int
	Name        string
	Description string
	Phase       RulePhase
	Operator    RuleOperator
	Pattern     string
	Target      string // e.g., "REQUEST_URI", "REQUEST_HEADERS", "REQUEST_BODY", "ARGS"
	Action      RuleAction
	Severity    string // "low", "medium", "high", "critical"
	Enabled     bool
	regex       *regexp.Regexp // compiled regex pattern
}

// Compile compiles the rule's regex pattern if needed
func (r *Rule) Compile() error {
	if r.Operator == OpRegex || r.Operator == OpNotRegex {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return err
		}
		r.regex = re
	}
	return nil
}

// Match checks if the rule matches the given data
func (r *Rule) Match(data string) bool {
	if !r.Enabled {
		return false
	}

	switch r.Operator {
	case OpContains:
		return strings.Contains(data, r.Pattern)
	case OpNotContains:
		return !strings.Contains(data, r.Pattern)
	case OpRegex:
		if r.regex == nil {
			return false
		}
		return r.regex.MatchString(data)
	case OpNotRegex:
		if r.regex == nil {
			return false
		}
		return !r.regex.MatchString(data)
	case OpStartsWith:
		return strings.HasPrefix(data, r.Pattern)
	case OpEndsWith:
		return strings.HasSuffix(data, r.Pattern)
	case OpEquals:
		return data == r.Pattern
	case OpHighEntropy:
		return calculateEntropy(data) > 4.0
	case OpSQLi:
		return detectSQLi(data)
	case OpXSS:
		return detectXSS(data)
	default:
		return false
	}
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	entropy := 0.0
	for _, f := range freq {
		p := f / float64(len(s))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// detectSQLi detects common SQL injection patterns
func detectSQLi(data string) bool {
	sqlPatterns := []string{
		"' OR '1'='1",
		"' OR 1=1",
		"'; DROP TABLE",
		"UNION SELECT",
		"' OR 'a'='a",
		"admin' --",
		"' /*",
		"*/ OR /*",
		"xp_",
		"sp_",
	}

	upperData := strings.ToUpper(data)
	for _, pattern := range sqlPatterns {
		if strings.Contains(upperData, strings.ToUpper(pattern)) {
			return true
		}
	}
	return false
}

// detectXSS detects common XSS patterns
func detectXSS(data string) bool {
	xssPatterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
		"<iframe",
		"<object",
		"<embed",
		"<img",
		"<svg",
	}

	lowerData := strings.ToLower(data)
	for _, pattern := range xssPatterns {
		if strings.Contains(lowerData, pattern) {
			return true
		}
	}
	return false
}
