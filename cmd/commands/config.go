package commands

import (
	"fmt"
	"os"

	"github.com/shieldcli/shieldcli/pkg/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration files",
	Long:  `Manage ShieldCLI configuration files`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		return configInit()
	},
}

var configExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export configuration to a different format",
	RunE: func(cmd *cobra.Command, args []string) error {
		return configExport()
	},
}

var (
	outputFile string
	exportFormat string
)

func init() {
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configExportCmd)

	configInitCmd.Flags().StringVar(&outputFile, "output", "shieldcli.yaml", "Output file path")
	configExportCmd.Flags().StringVar(&outputFile, "output", "", "Output file path")
	configExportCmd.Flags().StringVar(&exportFormat, "format", "terraform", "Export format: terraform, dockerfile")
	configExportCmd.MarkFlagRequired("output")
}

func configInit() error {
	// Check if file already exists
	if _, err := os.Stat(outputFile); err == nil {
		fmt.Printf("File %s already exists. Overwrite? (y/n): ", outputFile)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Create default configuration
	cfg := &config.ConfigFile{}
	cfg.Proxy.ListenPort = 8080
	cfg.Proxy.TargetURL = "http://localhost:3000"
	cfg.Proxy.Timeout = 30

	cfg.WAF.DefaultAction = "block"
	cfg.WAF.EnabledRules = []int{1001, 1002, 1003, 1004, 1005, 1006}

	cfg.Logging.TerminalEnabled = true
	cfg.Logging.TerminalLevel = "info"
	cfg.Logging.FilePath = "./shieldcli.log"
	cfg.Logging.FileFormat = "text"

	cfg.Gemini.Model = "gemini-2.5-flash"
	cfg.Gemini.Enabled = true
	cfg.Gemini.AnalysisThreshold = 5

	// Save configuration
	if err := config.SaveConfigFile(outputFile, cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		return err
	}

	fmt.Printf("Configuration file created: %s\n", outputFile)
	fmt.Println("Please edit the file and set your Gemini API key if you want to use AI analysis.")
	return nil
}

func configExport() error {
	// Load configuration from default file
	cfgFile, err := config.LoadConfigFile("shieldcli.yaml")
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		return err
	}

	var exportContent string

	switch exportFormat {
	case "terraform":
		exportContent = generateTerraformConfig(cfgFile)
	case "dockerfile":
		exportContent = generateDockerfileConfig(cfgFile)
	default:
		return fmt.Errorf("unsupported export format: %s", exportFormat)
	}

	// Write to output file
	if err := os.WriteFile(outputFile, []byte(exportContent), 0644); err != nil {
		fmt.Printf("Error writing export file: %v\n", err)
		return err
	}

	fmt.Printf("Configuration exported to: %s\n", outputFile)
	return nil
}

func generateTerraformConfig(cfg *config.ConfigFile) string {
	return fmt.Sprintf(`# ShieldCLI Terraform Configuration
# This is an example Terraform configuration for deploying ShieldCLI

resource "docker_container" "shieldcli" {
  name  = "shieldcli-waf"
  image = "shieldcli:latest"

  ports {
    internal = %d
    external = %d
  }

  env = [
    "PROXY_TO=%s",
    "LISTEN_PORT=%d",
    "GEMINI_API_KEY=${var.gemini_api_key}",
  ]

  volumes {
    host_path      = "${path.module}/shieldcli.yaml"
    container_path = "/etc/shieldcli/shieldcli.yaml"
    read_only      = true
  }
}

variable "gemini_api_key" {
  description = "Google Gemini API Key"
  type        = string
  sensitive   = true
}
`, cfg.Proxy.ListenPort, cfg.Proxy.ListenPort, cfg.Proxy.TargetURL, cfg.Proxy.ListenPort)
}

func generateDockerfileConfig(cfg *config.ConfigFile) string {
	return fmt.Sprintf(`# ShieldCLI Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o shieldcli ./cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/shieldcli .
COPY shieldcli.yaml /etc/shieldcli/shieldcli.yaml

EXPOSE %d

ENV PROXY_TO=%s
ENV LISTEN_PORT=%d

ENTRYPOINT ["./shieldcli", "run", "--proxy-to", "$PROXY_TO", "--port", "$LISTEN_PORT"]
`, cfg.Proxy.ListenPort, cfg.Proxy.TargetURL, cfg.Proxy.ListenPort)
}
