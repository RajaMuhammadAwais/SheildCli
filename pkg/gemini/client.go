package gemini

import (
	"context"
	"fmt"
	"strings"

	"github.com/shieldcli/shieldcli/pkg/logging"
	"google.golang.org/genai"
)

// Client represents the Gemini AI client
type Client struct {
	client *genai.Client
	model  string
	logger *logging.Logger
	ctx    context.Context
}

// AnalysisResult contains the AI analysis result
type AnalysisResult struct {
	IsMalicious bool
	Confidence  float64
	Explanation string
	Verdict     string
	SuggestedRule string
}

// NewClient creates a new Gemini client
func NewClient(apiKey, model string, logger *logging.Logger) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("Gemini API key is required")
	}

	ctx := context.Background()
	
	// Create client config with API key
	config := &genai.ClientConfig{
		APIKey: apiKey,
	}

	client, err := genai.NewClient(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	return &Client{
		client: client,
		model:  model,
		logger: logger,
		ctx:    ctx,
	}, nil
}

// AnalyzePayload sends a payload to Gemini for analysis
func (c *Client) AnalyzePayload(payload string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Analyze the following HTTP payload for potential security threats. 
Respond with ONLY a JSON object in this format (no markdown, no extra text):
{
  "is_malicious": true/false,
  "confidence": 0.0-1.0,
  "verdict": "malicious/suspicious/safe",
  "explanation": "brief explanation",
  "suggested_rule": "optional suggested WAF rule pattern"
}

Payload:
%s`, payload)

	resp, err := c.client.Models.GenerateContent(c.ctx, c.model, []*genai.Content{
		{
			Role: "user",
			Parts: []*genai.Part{
				{Text: prompt},
			},
		},
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze payload: %w", err)
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	// Extract text from response
	var result string
	for _, part := range resp.Candidates[0].Content.Parts {
		if part.Text != "" {
			result += part.Text
		}
	}

	// Parse the JSON response
	analysisResult := parseAnalysisResult(result)
	return analysisResult, nil
}

// SummarizeAttacks generates a summary of attack trends from logs
func (c *Client) SummarizeAttacks(logData string) (string, error) {
	prompt := fmt.Sprintf(`Analyze the following WAF logs and provide a brief summary of attack trends, 
common attack patterns, and recommendations for improving security rules.

WAF Logs:
%s

Provide a concise summary (2-3 paragraphs).`, logData)

	resp, err := c.client.Models.GenerateContent(c.ctx, c.model, []*genai.Content{
		{
			Role: "user",
			Parts: []*genai.Part{
				{Text: prompt},
			},
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to summarize attacks: %w", err)
	}

	if len(resp.Candidates) == 0 {
		return "", fmt.Errorf("no response from Gemini")
	}

	// Extract text from response
	var result string
	for _, part := range resp.Candidates[0].Content.Parts {
		if part.Text != "" {
			result += part.Text
		}
	}

	return result, nil
}

// Close closes the Gemini client
func (c *Client) Close() error {
	// The genai.Client doesn't have a Close method, so we just return nil
	return nil
}

// parseAnalysisResult parses the JSON response from Gemini
func parseAnalysisResult(jsonStr string) *AnalysisResult {
	result := &AnalysisResult{
		IsMalicious: false,
		Confidence:  0.0,
		Verdict:     "unknown",
		Explanation: "Failed to parse response",
	}

	// Simple JSON parsing (avoiding external dependencies)
	if strings.Contains(jsonStr, `"is_malicious": true`) {
		result.IsMalicious = true
	}

	// Extract verdict
	if strings.Contains(jsonStr, `"verdict": "malicious"`) {
		result.Verdict = "malicious"
	} else if strings.Contains(jsonStr, `"verdict": "suspicious"`) {
		result.Verdict = "suspicious"
	} else if strings.Contains(jsonStr, `"verdict": "safe"`) {
		result.Verdict = "safe"
	}

	// Extract confidence
	if idx := strings.Index(jsonStr, `"confidence":`); idx != -1 {
		start := idx + len(`"confidence":`)
		end := strings.Index(jsonStr[start:], ",")
		if end == -1 {
			end = strings.Index(jsonStr[start:], "}")
		}
		if end != -1 {
			confStr := strings.TrimSpace(jsonStr[start : start+end])
			fmt.Sscanf(confStr, "%f", &result.Confidence)
		}
	}

	// Extract explanation
	if idx := strings.Index(jsonStr, `"explanation":`); idx != -1 {
		start := idx + len(`"explanation": "`)
		end := strings.Index(jsonStr[start:], `"`)
		if end != -1 {
			result.Explanation = jsonStr[start : start+end]
		}
	}

	// Extract suggested rule
	if idx := strings.Index(jsonStr, `"suggested_rule":`); idx != -1 {
		start := idx + len(`"suggested_rule": "`)
		end := strings.Index(jsonStr[start:], `"`)
		if end != -1 {
			result.SuggestedRule = jsonStr[start : start+end]
		}
	}

	return result
}
