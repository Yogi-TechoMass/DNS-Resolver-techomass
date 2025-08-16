package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config holds all configuration options for the DNS resolver
type Config struct {
	// Input/Output options
	InputFile    string
	OutputFile   string
	LogFile      string
	OutputFormat string

	// DNS resolver options
	Resolvers     string
	ResolversFile string
	QueryTypes    string

	// Performance options
	QPS     int
	Timeout int
	Retries int
	Workers int

	// Security options
	SecurityChecks        bool
	DNSSECValidation      bool
	ProtocolDetection     bool
	SecurityScoring       bool
	CertificateValidation bool

	// Feature flags
	WildcardDetection bool
	Verbose           bool
	Quiet             bool
	Help              bool
	Version           bool
}

// GetDefaultResolvers returns a list of well-known public DNS resolvers
func GetDefaultResolvers() []string {
	return []string{
		"8.8.8.8:53",     // Google DNS
		"8.8.4.4:53",     // Google DNS
		"1.1.1.1:53",     // Cloudflare DNS
		"1.0.0.1:53",     // Cloudflare DNS
		"208.67.222.222:53", // OpenDNS
		"208.67.220.220:53", // OpenDNS
		"9.9.9.9:53",     // Quad9 DNS
		"149.112.112.112:53", // Quad9 DNS
	}
}

// LoadConfig loads configuration from environment variables and files
func LoadConfig(config *Config) error {
	// Load additional resolvers from environment
	if envResolvers := os.Getenv("DNS_RESOLVERS"); envResolvers != "" {
		if config.Resolvers != "" {
			config.Resolvers += "," + envResolvers
		} else {
			config.Resolvers = envResolvers
		}
	}

	// Load resolvers file from environment
	if envResolversFile := os.Getenv("DNS_RESOLVERS_FILE"); envResolversFile != "" && config.ResolversFile == "" {
		config.ResolversFile = envResolversFile
	}

	// Load output file from environment
	if envOutputFile := os.Getenv("DNS_OUTPUT_FILE"); envOutputFile != "" && config.OutputFile == "" {
		config.OutputFile = envOutputFile
	}

	return nil
}

// ValidateConfig validates the configuration options
func ValidateConfig(config *Config) error {
	// Validate output format
	validFormats := map[string]bool{
		"simple": true,
		"json":   true,
		"csv":    true,
	}

	if !validFormats[config.OutputFormat] {
		return fmt.Errorf("invalid output format: %s (must be simple, json, or csv)", config.OutputFormat)
	}

	// Validate query types
	validTypes := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"NS": true, "TXT": true, "SOA": true, "PTR": true, "SRV": true,
	}

	if config.QueryTypes != "" {
		types := strings.Split(strings.ToUpper(config.QueryTypes), ",")
		for _, t := range types {
			t = strings.TrimSpace(t)
			if !validTypes[t] {
				// Check if it's a numeric type
				if !isNumericDNSType(t) {
					return fmt.Errorf("invalid query type: %s", t)
				}
			}
		}
	}

	// Validate numeric options
	if config.QPS <= 0 {
		return fmt.Errorf("QPS must be greater than 0")
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	if config.Retries < 0 {
		return fmt.Errorf("retries cannot be negative")
	}

	if config.Workers <= 0 {
		return fmt.Errorf("workers must be greater than 0")
	}

	return nil
}

// isNumericDNSType checks if a string represents a valid numeric DNS type
func isNumericDNSType(s string) bool {
	// Simple validation for numeric DNS types (1-65535)
	if len(s) == 0 {
		return false
	}

	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// SaveConfig saves the current configuration to a file
func SaveConfig(config *Config, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write configuration options
	fmt.Fprintf(writer, "# DNS Resolver Configuration\n")
	fmt.Fprintf(writer, "input_file=%s\n", config.InputFile)
	fmt.Fprintf(writer, "output_file=%s\n", config.OutputFile)
	fmt.Fprintf(writer, "log_file=%s\n", config.LogFile)
	fmt.Fprintf(writer, "resolvers=%s\n", config.Resolvers)
	fmt.Fprintf(writer, "resolvers_file=%s\n", config.ResolversFile)
	fmt.Fprintf(writer, "query_types=%s\n", config.QueryTypes)
	fmt.Fprintf(writer, "output_format=%s\n", config.OutputFormat)
	fmt.Fprintf(writer, "qps=%d\n", config.QPS)
	fmt.Fprintf(writer, "timeout=%d\n", config.Timeout)
	fmt.Fprintf(writer, "retries=%d\n", config.Retries)
	fmt.Fprintf(writer, "workers=%d\n", config.Workers)
	fmt.Fprintf(writer, "security_checks=%t\n", config.SecurityChecks)
	fmt.Fprintf(writer, "dnssec_validation=%t\n", config.DNSSECValidation)
	fmt.Fprintf(writer, "protocol_detection=%t\n", config.ProtocolDetection)
	fmt.Fprintf(writer, "security_scoring=%t\n", config.SecurityScoring)
	fmt.Fprintf(writer, "certificate_validation=%t\n", config.CertificateValidation)
	fmt.Fprintf(writer, "wildcard_detection=%t\n", config.WildcardDetection)
	fmt.Fprintf(writer, "verbose=%t\n", config.Verbose)
	fmt.Fprintf(writer, "quiet=%t\n", config.Quiet)

	return nil
}

// LoadConfigFromFile loads configuration from a file
func LoadConfigFromFile(filename string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "input_file":
			config.InputFile = value
		case "output_file":
			config.OutputFile = value
		case "log_file":
			config.LogFile = value
		case "resolvers":
			config.Resolvers = value
		case "resolvers_file":
			config.ResolversFile = value
		case "query_types":
			config.QueryTypes = value
		case "output_format":
			config.OutputFormat = value
		case "security_checks":
			config.SecurityChecks = value == "true"
		case "dnssec_validation":
			config.DNSSECValidation = value == "true"
		case "protocol_detection":
			config.ProtocolDetection = value == "true"
		case "security_scoring":
			config.SecurityScoring = value == "true"
		case "certificate_validation":
			config.CertificateValidation = value == "true"
		case "wildcard_detection":
			config.WildcardDetection = value == "true"
		case "verbose":
			config.Verbose = value == "true"
		case "quiet":
			config.Quiet = value == "true"
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	return config, nil
}
