package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// InputValidator validates input domains and provides input processing utilities
type InputValidator struct {
	domainRegex *regexp.Regexp
}

// NewInputValidator creates a new input validator
func NewInputValidator() *InputValidator {
	// RFC-compliant domain name regex
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	
	return &InputValidator{
		domainRegex: domainRegex,
	}
}

// ValidateDomain validates if a string is a valid domain name
func (iv *InputValidator) ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	// Check length
	if len(domain) > 253 {
		return fmt.Errorf("domain name too long (max 253 characters)")
	}

	// Check for valid characters and format
	if !iv.domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain name format")
	}

	// Check individual labels
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("empty label in domain name")
		}
		if len(label) > 63 {
			return fmt.Errorf("label too long (max 63 characters): %s", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label cannot start or end with hyphen: %s", label)
		}
	}

	return nil
}

// ValidateIP validates if a string is a valid IP address
func (iv *InputValidator) ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// NormalizeDomain normalizes a domain name to standard format
func (iv *InputValidator) NormalizeDomain(domain string) string {
	// Convert to lowercase
	domain = strings.ToLower(domain)
	
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")
	
	// Remove leading/trailing whitespace
	domain = strings.TrimSpace(domain)
	
	return domain
}

// ProcessInputFile processes an input file and returns validated domains
func (iv *InputValidator) ProcessInputFile(filename string) ([]string, []error, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open input file: %v", err)
	}
	defer file.Close()

	var domains []string
	var validationErrors []error
	lineNumber := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle multiple domains per line (space or comma separated)
		lineDomains := iv.parseLine(line)
		
		for _, domain := range lineDomains {
			domain = iv.NormalizeDomain(domain)
			
			if err := iv.ValidateDomain(domain); err != nil {
				validationErrors = append(validationErrors, 
					fmt.Errorf("line %d: %v", lineNumber, err))
				continue
			}
			
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return domains, validationErrors, fmt.Errorf("error reading input file: %v", err)
	}

	return domains, validationErrors, nil
}

// parseLine parses a line that may contain multiple domains
func (iv *InputValidator) parseLine(line string) []string {
	// Split by common separators
	separators := []string{",", ";", " ", "\t"}
	
	domains := []string{line}
	
	for _, sep := range separators {
		var newDomains []string
		for _, domain := range domains {
			parts := strings.Split(domain, sep)
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					newDomains = append(newDomains, part)
				}
			}
		}
		domains = newDomains
	}
	
	return domains
}

// DetectInputFormat detects the format of input data
func (iv *InputValidator) DetectInputFormat(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	domainCount := 0
	ipCount := 0
	
	// Sample first few lines
	for scanner.Scan() && lineCount < 10 {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		lineCount++
		
		// Check if line contains domains or IPs
		domains := iv.parseLine(line)
		for _, domain := range domains {
			domain = iv.NormalizeDomain(domain)
			
			if iv.ValidateIP(domain) == nil {
				ipCount++
			} else if iv.ValidateDomain(domain) == nil {
				domainCount++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	// Determine format based on content
	if ipCount > domainCount {
		return "ip_list", nil
	} else if domainCount > 0 {
		return "domain_list", nil
	} else {
		return "unknown", nil
	}
}

// GenerateSubdomains generates common subdomains for a given domain
func (iv *InputValidator) GenerateSubdomains(domain string) []string {
	commonSubdomains := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
		"admin", "administrator", "root", "test", "staging", "dev",
		"api", "app", "mobile", "m", "blog", "shop", "store",
		"cdn", "static", "media", "images", "img", "css", "js",
		"vpn", "proxy", "gateway", "firewall", "router", "switch",
		"dns", "ns", "ns1", "ns2", "mx", "mx1", "mx2",
		"secure", "ssl", "tls", "https", "sftp", "ssh",
	}

	var subdomains []string
	for _, sub := range commonSubdomains {
		subdomain := sub + "." + domain
		if iv.ValidateDomain(subdomain) == nil {
			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains
}

// ExtractDomainsFromURL extracts domain names from URLs
func (iv *InputValidator) ExtractDomainsFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "ftp://")
	
	// Remove path and query parameters
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "#"); idx != -1 {
		url = url[:idx]
	}
	
	// Remove port
	if idx := strings.LastIndex(url, ":"); idx != -1 {
		if port := url[idx+1:]; isNumeric(port) {
			url = url[:idx]
		}
	}
	
	return url
}

// isNumeric checks if a string is numeric
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// FilterDuplicates removes duplicate domains from a slice
func (iv *InputValidator) FilterDuplicates(domains []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, domain := range domains {
		domain = iv.NormalizeDomain(domain)
		if !seen[domain] {
			seen[domain] = true
			result = append(result, domain)
		}
	}
	
	return result
}

// SortDomains sorts domains in a logical order
func (iv *InputValidator) SortDomains(domains []string) []string {
	// Simple alphabetical sort for now
	// Could be enhanced with more sophisticated sorting logic
	result := make([]string, len(domains))
	copy(result, domains)
	
	// Bubble sort (simple implementation)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i] > result[j] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	
	return result
}

// GetDomainDepth returns the depth of a domain (number of labels)
func (iv *InputValidator) GetDomainDepth(domain string) int {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return 0
	}
	return len(strings.Split(domain, "."))
}

// GetRootDomain extracts the root domain from a subdomain
func (iv *InputValidator) GetRootDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	
	if len(parts) <= 2 {
		return domain
	}
	
	// Return the last two parts (assuming standard TLD)
	return strings.Join(parts[len(parts)-2:], ".")
}
