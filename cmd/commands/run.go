package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shieldcli/shieldcli/pkg/config"
	"github.com/shieldcli/shieldcli/pkg/logging"
	"github.com/shieldcli/shieldcli/pkg/proxy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	proxyTo    string
	port       int
	dryRun     bool
	interactive bool
	geminiKey  string
	logFile    string
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the ShieldCLI WAF proxy",
	Long: `Start the ShieldCLI WAF proxy to intercept and protect HTTP traffic.
	
Example:
  shieldcli run --proxy-to http://localhost:3000 --port 8080`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runWAF()
	},
}

func init() {
	runCmd.Flags().StringVar(&proxyTo, "proxy-to", "", "Target application URL to forward traffic to (required)")
	runCmd.Flags().IntVar(&port, "port", 8080, "Local port to listen on")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Enable dry-run mode (log but don't block)")
	runCmd.Flags().BoolVar(&interactive, "interactive", false, "Enable interactive mode (approve/deny requests)")
	runCmd.Flags().StringVar(&geminiKey, "gemini-key", "", "Google Gemini API key (or set GEMINI_API_KEY env var)")
	runCmd.Flags().StringVar(&logFile, "log-file", "", "Path to export WAF logs")

	// Mark required flags
	runCmd.MarkFlagRequired("proxy-to")
}

func runWAF() error {
	// Load configuration
	cfg := &config.Config{
		ProxyTo:     proxyTo,
		Port:        port,
		DryRun:      dryRun,
		Interactive: interactive,
		GeminiKey:   geminiKey,
		LogFile:     logFile,
	}

	// Override with viper config if available
	if viper.IsSet("proxy.target_url") {
		cfg.ProxyTo = viper.GetString("proxy.target_url")
	}
	if viper.IsSet("proxy.listen_port") {
		cfg.Port = viper.GetInt("proxy.listen_port")
	}
	if viper.IsSet("waf.default_action") {
		cfg.WAFAction = viper.GetString("waf.default_action")
	}
	if viper.IsSet("logging.file_path") {
		cfg.LogFile = viper.GetString("logging.file_path")
	}
	if viper.IsSet("gemini.api_key") {
		cfg.GeminiKey = viper.GetString("gemini.api_key")
	}

	// Initialize logger
	logger := logging.NewLogger(cfg.LogFile)
	defer logger.Close()

	logger.Info("ShieldCLI starting...")
	logger.Info("Target: %s", cfg.ProxyTo)
	logger.Info("Listen: 0.0.0.0:%d", cfg.Port)
	if cfg.DryRun {
		logger.Warn("Running in DRY-RUN mode (no blocking)")
	}
	if cfg.Interactive {
		logger.Info("Running in INTERACTIVE mode")
	}

	// Create and start proxy
	p, err := proxy.NewProxy(cfg, logger)
	if err != nil {
		logger.Error("Failed to create proxy: %v", err)
		return err
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal: %v", sig)
		p.Stop()
	}()

	// Start proxy
	fmt.Printf("ShieldCLI is running on 0.0.0.0:%d\n", cfg.Port)
	fmt.Printf("Forwarding to: %s\n", cfg.ProxyTo)
	fmt.Println("Press Ctrl+C to stop")

	if err := p.Start(); err != nil {
		logger.Error("Proxy error: %v", err)
		return err
	}

	return nil
}
