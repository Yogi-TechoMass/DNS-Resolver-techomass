package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// WildcardDetector detects DNS wildcard responses
type WildcardDetector struct {
	resolverPool *ResolverPool
	logger       *log.Logger
	cache        map[string]*WildcardInfo
	mutex        sync.RWMutex
	cacheTTL     time.Duration
}

// WildcardInfo contains information about wildcard detection for a domain
type WildcardInfo struct {
	IsWildcard     bool
	WildcardIPs    []string
	LastChecked    time.Time
	TestSubdomains []string
}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector(resolverPool *ResolverPool, logger *log.Logger) *WildcardDetector {
	return &WildcardDetector{
		resolverPool: resolverPool,
		logger:       logger,
		cache:        make(map[string]*WildcardInfo),
		cacheTTL:     30 * time.Minute, // Cache wildcard info for 30 minutes
	}
}

// IsWildcard checks if a DNS result represents a wildcard response
func (wd *WildcardDetector) IsWildcard(result *DNSResult) bool {
	if result.Error != nil || result.Response == nil {
		return false
	}

	// Extract domain from the result
	domain := result.Domain
	if domain == "" {
		return false
	}

	// Get the root domain for wildcard checking
	rootDomain := wd.getRootDomain(domain)
	
	// Check cache first
	wildcardInfo, exists := wd.getCachedWildcardInfo(rootDomain)
	if exists && time.Since(wildcardInfo.LastChecked) < wd.cacheTTL {
		return wd.matchesWildcardPattern(result, wildcardInfo)
	}

	// Perform wildcard detection
	wildcardInfo = wd.detectWildcard(rootDomain)
	
	// Cache the result
	wd.cacheWildcardInfo(rootDomain, wildcardInfo)

	return wd.matchesWildcardPattern(result, wildcardInfo)
}

// detectWildcard performs wildcard detection for a domain
func (wd *WildcardDetector) detectWildcard(domain string) *WildcardInfo {
	info := &WildcardInfo{
		IsWildcard:     false,
		WildcardIPs:    make([]string, 0),
		LastChecked:    time.Now(),
		TestSubdomains: make([]string, 0),
	}

	// Generate random subdomains for testing
	testSubdomains := wd.generateTestSubdomains(domain, 5)
	info.TestSubdomains = testSubdomains

	var wildcardIPs []string
	wildcardCount := 0

	// Test each random subdomain
	for _, testDomain := range testSubdomains {
		ips := wd.queryDomain(testDomain)
		if len(ips) > 0 {
			wildcardCount++
			wildcardIPs = append(wildcardIPs, ips...)
		}
	}

	// If most test subdomains resolve, it's likely a wildcard
	if wildcardCount >= len(testSubdomains)/2 {
		info.IsWildcard = true
		info.WildcardIPs = wd.deduplicateIPs(wildcardIPs)
		wd.logger.Printf("Wildcard detected for %s: %v", domain, info.WildcardIPs)
	}

	return info
}

// generateTestSubdomains generates random subdomains for wildcard testing
func (wd *WildcardDetector) generateTestSubdomains(domain string, count int) []string {
	var testSubdomains []string
	
	for i := 0; i < count; i++ {
		randomString := wd.generateRandomString(12)
		testDomain := fmt.Sprintf("%s.%s", randomString, domain)
		testSubdomains = append(testSubdomains, testDomain)
	}

	return testSubdomains
}

// generateRandomString generates a random string of specified length
func (wd *WildcardDetector) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// queryDomain performs a DNS query and returns IP addresses
func (wd *WildcardDetector) queryDomain(domain string) []string {
	resolver := wd.resolverPool.GetResolver()
	if resolver == nil {
		return nil
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, _, err := resolver.ExchangeContext(ctx, msg, resolver.Address)
	if err != nil {
		return nil
	}

	var ips []string
	for _, rr := range response.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	return ips
}

// matchesWildcardPattern checks if a result matches a wildcard pattern
func (wd *WildcardDetector) matchesWildcardPattern(result *DNSResult, wildcardInfo *WildcardInfo) bool {
	if !wildcardInfo.IsWildcard {
		return false
	}

	// Extract IPs from the result
	resultIPs := wd.extractIPsFromResult(result)
	
	// Check if any result IP matches wildcard IPs
	for _, resultIP := range resultIPs {
		for _, wildcardIP := range wildcardInfo.WildcardIPs {
			if resultIP == wildcardIP {
				return true
			}
		}
	}

	return false
}

// extractIPsFromResult extracts IP addresses from a DNS result
func (wd *WildcardDetector) extractIPsFromResult(result *DNSResult) []string {
	var ips []string

	if result.Response == nil {
		return ips
	}

	for _, rr := range result.Response.Answer {
		switch record := rr.(type) {
		case *dns.A:
			ips = append(ips, record.A.String())
		case *dns.AAAA:
			ips = append(ips, record.AAAA.String())
		}
	}

	return ips
}

// getRootDomain extracts the root domain from a subdomain
func (wd *WildcardDetector) getRootDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	
	if len(parts) <= 2 {
		return domain
	}
	
	// Return the last two parts (assuming standard TLD)
	return strings.Join(parts[len(parts)-2:], ".")
}

// getCachedWildcardInfo retrieves wildcard info from cache
func (wd *WildcardDetector) getCachedWildcardInfo(domain string) (*WildcardInfo, bool) {
	wd.mutex.RLock()
	defer wd.mutex.RUnlock()
	
	info, exists := wd.cache[domain]
	return info, exists
}

// cacheWildcardInfo stores wildcard info in cache
func (wd *WildcardDetector) cacheWildcardInfo(domain string, info *WildcardInfo) {
	wd.mutex.Lock()
	defer wd.mutex.Unlock()
	
	wd.cache[domain] = info
}

// deduplicateIPs removes duplicate IP addresses
func (wd *WildcardDetector) deduplicateIPs(ips []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip)
		}
	}
	
	return result
}

// ClearCache clears the wildcard detection cache
func (wd *WildcardDetector) ClearCache() {
	wd.mutex.Lock()
	defer wd.mutex.Unlock()
	
	wd.cache = make(map[string]*WildcardInfo)
	wd.logger.Println("Wildcard detection cache cleared")
}

// GetCacheStats returns cache statistics
func (wd *WildcardDetector) GetCacheStats() map[string]interface{} {
	wd.mutex.RLock()
	defer wd.mutex.RUnlock()
	
	wildcardCount := 0
	expiredCount := 0
	
	for _, info := range wd.cache {
		if info.IsWildcard {
			wildcardCount++
		}
		if time.Since(info.LastChecked) > wd.cacheTTL {
			expiredCount++
		}
	}
	
	return map[string]interface{}{
		"total_entries":    len(wd.cache),
		"wildcard_domains": wildcardCount,
		"expired_entries":  expiredCount,
		"cache_ttl_minutes": int(wd.cacheTTL.Minutes()),
	}
}

// CleanupExpiredEntries removes expired entries from cache
func (wd *WildcardDetector) CleanupExpiredEntries() {
	wd.mutex.Lock()
	defer wd.mutex.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for domain, info := range wd.cache {
		if now.Sub(info.LastChecked) > wd.cacheTTL {
			delete(wd.cache, domain)
			expiredCount++
		}
	}
	
	if expiredCount > 0 {
		wd.logger.Printf("Cleaned up %d expired wildcard cache entries", expiredCount)
	}
}

// StartCacheCleanup starts a background goroutine to periodically clean up expired cache entries
func (wd *WildcardDetector) StartCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute) // Cleanup every 15 minutes
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			wd.CleanupExpiredEntries()
		case <-ctx.Done():
			return
		}
	}
}

// DetectWildcardSupport checks if a domain supports wildcard DNS
func (wd *WildcardDetector) DetectWildcardSupport(domain string) *WildcardInfo {
	wd.mutex.RLock()
	cached, exists := wd.cache[domain]
	wd.mutex.RUnlock()
	
	if exists && time.Since(cached.LastChecked) < wd.cacheTTL {
		return cached
	}
	
	// Perform fresh detection
	info := wd.detectWildcard(domain)
	wd.cacheWildcardInfo(domain, info)
	
	return info
}

// ValidateNonWildcard verifies that a domain is not a wildcard response
func (wd *WildcardDetector) ValidateNonWildcard(domain string) bool {
	info := wd.DetectWildcardSupport(wd.getRootDomain(domain))
	
	if !info.IsWildcard {
		return true
	}
	
	// Even if the domain has wildcard support, check if this specific subdomain
	// has a legitimate record by comparing with wildcard IPs
	actualIPs := wd.queryDomain(domain)
	
	// If the IPs don't match wildcard IPs, it's a legitimate record
	for _, actualIP := range actualIPs {
		isWildcard := false
		for _, wildcardIP := range info.WildcardIPs {
			if actualIP == wildcardIP {
				isWildcard = true
				break
			}
		}
		if !isWildcard {
			return true
		}
	}
	
	return false
}

// GetWildcardReport generates a report of wildcard domains
func (wd *WildcardDetector) GetWildcardReport() map[string]*WildcardInfo {
	wd.mutex.RLock()
	defer wd.mutex.RUnlock()
	
	report := make(map[string]*WildcardInfo)
	
	for domain, info := range wd.cache {
		if info.IsWildcard {
			// Create a copy to avoid concurrent access issues
			reportInfo := &WildcardInfo{
				IsWildcard:     info.IsWildcard,
				WildcardIPs:    append([]string(nil), info.WildcardIPs...),
				LastChecked:    info.LastChecked,
				TestSubdomains: append([]string(nil), info.TestSubdomains...),
			}
			report[domain] = reportInfo
		}
	}
	
	return report
}
