package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ConfigFile represents the YAML configuration file structure
type ConfigFile struct {
	Proxy struct {
		ListenPort int    `yaml:"listen_port"`
		TargetURL  string `yaml:"target_url"`
		Timeout    int    `yaml:"timeout"`
	} `yaml:"proxy"`

	WAF struct {
		DefaultAction string `yaml:"default_action"`
		EnabledRules  []int  `yaml:"enabled_rules"`
	} `yaml:"waf"`

	Logging struct {
		TerminalEnabled bool   `yaml:"terminal_enabled"`
		TerminalLevel   string `yaml:"terminal_level"`
		FilePath        string `yaml:"file_path"`
		FileFormat      string `yaml:"file_format"`
	} `yaml:"logging"`

	Gemini struct {
		APIKey              string `yaml:"api_key"`
		Model               string `yaml:"model"`
		Enabled             bool   `yaml:"enabled"`
		AnalysisThreshold   int    `yaml:"analysis_threshold"`
	} `yaml:"gemini"`

	CustomRules []struct {
		ID          int    `yaml:"id"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Phase       string `yaml:"phase"`
		Operator    string `yaml:"operator"`
		Pattern     string `yaml:"pattern"`
		Target      string `yaml:"target"`
		Action      string `yaml:"action"`
		Severity    string `yaml:"severity"`
		Enabled     bool   `yaml:"enabled"`
	} `yaml:"custom_rules"`
}

// LoadConfigFile loads a YAML configuration file
func LoadConfigFile(filePath string) (*ConfigFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// SaveConfigFile saves a configuration to a YAML file
func SaveConfigFile(filePath string, cfg *ConfigFile) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
