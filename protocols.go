package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ProtocolDetector detects support for various DNS security protocols
type ProtocolDetector struct {
	logger     *log.Logger
	httpClient *http.Client
}

// NewProtocolDetector creates a new protocol detector
func NewProtocolDetector(logger *log.Logger) *ProtocolDetector {
	return &ProtocolDetector{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		},
	}
}

// DetectSupport detects protocol support for a given domain
func (pd *ProtocolDetector) DetectSupport(domain string) *ProtocolSupport {
	support := &ProtocolSupport{
		DoH:           false,
		DoT:           false,
		DNSSEC:        false,
		HTTPSRedirect: false,
	}

	// Clean domain name
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	// Detect DNS over HTTPS (DoH) support
	support.DoH = pd.detectDoHSupport(domain)

	// Detect DNS over TLS (DoT) support
	support.DoT = pd.detectDoTSupport(domain)

	// Detect DNSSEC support
	support.DNSSEC = pd.detectDNSSECSupport(domain)

	// Check for HTTPS redirect
	support.HTTPSRedirect = pd.detectHTTPSRedirect(domain)

	return support
}

// detectDoHSupport checks if a domain supports DNS over HTTPS
func (pd *ProtocolDetector) detectDoHSupport(domain string) bool {
	// Common DoH endpoints to check
	dohEndpoints := []string{
		fmt.Sprintf("https://%s/dns-query", domain),
		fmt.Sprintf("https://dns.%s/dns-query", domain),
		fmt.Sprintf("https://%s/resolve", domain),
		fmt.Sprintf("https://dns.%s/resolve", domain),
	}

	for _, endpoint := range dohEndpoints {
		if pd.testDoHEndpoint(endpoint) {
			pd.logger.Printf("DoH support detected for %s at %s", domain, endpoint)
			return true
		}
	}

	// Check for well-known DoH providers
	if pd.isWellKnownDoHProvider(domain) {
		return true
	}

	return false
}

// testDoHEndpoint tests a specific DoH endpoint
func (pd *ProtocolDetector) testDoHEndpoint(endpoint string) bool {
	// Create a simple DNS query
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// Convert to wire format
	wire, err := msg.Pack()
	if err != nil {
		return false
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(string(wire)))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Set timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Perform request
	resp, err := pd.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if response indicates DoH support
	return resp.StatusCode == http.StatusOK && 
		   strings.Contains(resp.Header.Get("Content-Type"), "application/dns-message")
}

// detectDoTSupport checks if a domain supports DNS over TLS
func (pd *ProtocolDetector) detectDoTSupport(domain string) bool {
	// Common DoT ports and configurations
	dotEndpoints := []string{
		fmt.Sprintf("%s:853", domain),
		fmt.Sprintf("dns.%s:853", domain),
		fmt.Sprintf("%s:443", domain), // Some providers use 443
	}

	for _, endpoint := range dotEndpoints {
		if pd.testDoTEndpoint(endpoint) {
			pd.logger.Printf("DoT support detected for %s at %s", domain, endpoint)
			return true
		}
	}

	// Check for well-known DoT providers
	if pd.isWellKnownDoTProvider(domain) {
		return true
	}

	return false
}

// testDoTEndpoint tests a specific DoT endpoint
func (pd *ProtocolDetector) testDoTEndpoint(endpoint string) bool {
	// Create DNS client with TLS
	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 5 * time.Second,
	}

	// Create test query
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// Attempt TLS connection and query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.ExchangeContext(ctx, msg, endpoint)
	return err == nil
}

// detectDNSSECSupport checks if a domain has DNSSEC enabled
func (pd *ProtocolDetector) detectDNSSECSupport(domain string) bool {
	// Create DNS client
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	// Query for DNSKEY record
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true) // Enable EDNS0 with DO bit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return false
	}

	// Check for DNSKEY records
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeDNSKEY {
			return true
		}
	}

	// Check for DS record at parent domain
	return pd.checkDSRecord(domain)
}

// checkDSRecord checks for DS record at the parent domain
func (pd *ProtocolDetector) checkDSRecord(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Get parent domain
	parentDomain := strings.Join(parts[1:], ".")
	if parentDomain == "" {
		return false
	}

	client := &dns.Client{Timeout: 5 * time.Second}
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDS)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil {
		return false
	}

	// Check for DS records
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeDS {
			return true
		}
	}

	return false
}

// detectHTTPSRedirect checks if HTTP redirects to HTTPS
func (pd *ProtocolDetector) detectHTTPSRedirect(domain string) bool {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects, we want to detect them
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("http://%s", domain)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check for redirect to HTTPS
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		return strings.HasPrefix(location, "https://")
	}

	return false
}

// isWellKnownDoHProvider checks if domain is a known DoH provider
func (pd *ProtocolDetector) isWellKnownDoHProvider(domain string) bool {
	knownProviders := map[string]bool{
		"cloudflare-dns.com": true,
		"dns.google":         true,
		"dns.quad9.net":      true,
		"security.cloudflare-dns.com": true,
		"family.cloudflare-dns.com":   true,
		"dns64.cloudflare-dns.com":    true,
		"1dot1dot1dot1.cloudflare-dns.com": true,
	}

	return knownProviders[domain]
}

// isWellKnownDoTProvider checks if domain is a known DoT provider
func (pd *ProtocolDetector) isWellKnownDoTProvider(domain string) bool {
	knownProviders := map[string]bool{
		"cloudflare-dns.com": true,
		"dns.google":         true,
		"dns.quad9.net":      true,
		"one.one.one.one":    true,
		"1dot1dot1dot1.cloudflare-dns.com": true,
	}

	return knownProviders[domain]
}

// GetProtocolRecommendations provides recommendations for improving protocol security
func (pd *ProtocolDetector) GetProtocolRecommendations(support *ProtocolSupport, domain string) []string {
	var recommendations []string

	if !support.DoH {
		recommendations = append(recommendations, 
			"Consider implementing DNS over HTTPS (DoH) for enhanced privacy")
	}

	if !support.DoT {
		recommendations = append(recommendations, 
			"Consider implementing DNS over TLS (DoT) for encrypted DNS queries")
	}

	if !support.DNSSEC {
		recommendations = append(recommendations, 
			"Implement DNSSEC to ensure DNS response authenticity and integrity")
	}

	if !support.HTTPSRedirect {
		recommendations = append(recommendations, 
			"Configure automatic HTTP to HTTPS redirect for better security")
	}

	return recommendations
}

// TestConnectivity tests basic connectivity to various protocol endpoints
func (pd *ProtocolDetector) TestConnectivity(domain string) map[string]bool {
	results := make(map[string]bool)

	// Test standard DNS (UDP)
	results["DNS_UDP"] = pd.testUDPConnectivity(domain)

	// Test standard DNS (TCP)
	results["DNS_TCP"] = pd.testTCPConnectivity(domain)

	// Test DoT connectivity
	results["DoT"] = pd.detectDoTSupport(domain)

	// Test HTTP connectivity
	results["HTTP"] = pd.testHTTPConnectivity(domain)

	// Test HTTPS connectivity
	results["HTTPS"] = pd.testHTTPSConnectivity(domain)

	return results
}

// testUDPConnectivity tests UDP DNS connectivity
func (pd *ProtocolDetector) testUDPConnectivity(domain string) bool {
	conn, err := net.DialTimeout("udp", domain+":53", 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// testTCPConnectivity tests TCP DNS connectivity
func (pd *ProtocolDetector) testTCPConnectivity(domain string) bool {
	conn, err := net.DialTimeout("tcp", domain+":53", 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// testHTTPConnectivity tests HTTP connectivity
func (pd *ProtocolDetector) testHTTPConnectivity(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://"+domain, nil)
	if err != nil {
		return false
	}

	resp, err := pd.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500
}

// testHTTPSConnectivity tests HTTPS connectivity
func (pd *ProtocolDetector) testHTTPSConnectivity(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://"+domain, nil)
	if err != nil {
		return false
	}

	resp, err := pd.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 500
}
