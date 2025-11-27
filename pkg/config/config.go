package config

// Config holds the main configuration for ShieldCLI
type Config struct {
	// Proxy settings
	ProxyTo     string
	Port        int
	Timeout     int // in seconds

	// WAF settings
	CRSPath       string
	WAFAction     string // 'block', 'log', 'dry-run'
	AnomalyThreshold int

	// Logging settings
	LogFile    string
	LogFormat  string // 'json' or 'text'
	LogLevel   string // 'info', 'warn', 'error', 'debug'

	// Gemini settings
	GeminiKey string
	GeminiModel string

	// Runtime flags
	DryRun      bool
	Interactive bool
}

// NewConfig creates a new default configuration
func NewConfig() *Config {
	return &Config{
		Port:              8080,
		Timeout:           30,
		WAFAction:         "block",
		AnomalyThreshold:  5,
		LogFormat:         "json",
		LogLevel:          "info",
		GeminiModel:       "gemini-2.5-flash",
		DryRun:            false,
		Interactive:       false,
	}
}
