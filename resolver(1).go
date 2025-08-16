package main

import (
        "bufio"
        "context"
        "fmt"
        "log"
        "math/rand"
        "net"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/miekg/dns"
)

// DNSResolver represents a single DNS resolver with enhanced capabilities
type DNSResolver struct {
        Address    string
        Client     *dns.Client
        TLSClient  *dns.Client // For DNS over TLS
        Statistics ResolverStats
}

// ResolverStats tracks statistics for individual resolvers
type ResolverStats struct {
        Queries   int64
        Successes int64
        Failures  int64
        AvgTime   time.Duration
        mutex     sync.RWMutex
}

// ResolverPool manages a pool of DNS resolvers with load balancing
type ResolverPool struct {
        resolvers []*DNSResolver
        mutex     sync.RWMutex
        index     int
        logger    *log.Logger
}

// NewResolverPool creates a new resolver pool with enhanced features
func NewResolverPool(config *Config, logger *log.Logger) *ResolverPool {
        pool := &ResolverPool{
                resolvers: make([]*DNSResolver, 0),
                logger:    logger,
        }

        // Load resolvers from various sources
        var resolverAddresses []string

        // Load from command line
        if config.Resolvers != "" {
                addresses := strings.Split(config.Resolvers, ",")
                for _, addr := range addresses {
                        addr = strings.TrimSpace(addr)
                        if addr != "" {
                                resolverAddresses = append(resolverAddresses, addr)
                        }
                }
        }

        // Load from file
        if config.ResolversFile != "" {
                fileAddresses, err := loadResolversFromFile(config.ResolversFile)
                if err != nil {
                        logger.Printf("Error loading resolvers from file: %v", err)
                } else {
                        resolverAddresses = append(resolverAddresses, fileAddresses...)
                }
        }

        // Use defaults if no resolvers specified
        if len(resolverAddresses) == 0 {
                resolverAddresses = GetDefaultResolvers()
                logger.Println("Using default DNS resolvers")
        }

        // Create resolver instances
        for _, addr := range resolverAddresses {
                if resolver := pool.createResolver(addr, config.Timeout); resolver != nil {
                        pool.resolvers = append(pool.resolvers, resolver)
                }
        }

        logger.Printf("Initialized resolver pool with %d resolvers", len(pool.resolvers))
        return pool
}

// createResolver creates a new DNS resolver with proper address formatting and validation
func (p *ResolverPool) createResolver(address string, timeout int) *DNSResolver {
        // Ensure address has port
        if !strings.Contains(address, ":") {
                address = address + ":53"
        }

        // Validate address
        if _, _, err := net.SplitHostPort(address); err != nil {
                p.logger.Printf("Invalid resolver address: %s", address)
                return nil
        }

        // Create UDP client
        client := &dns.Client{
                Timeout: time.Duration(timeout) * time.Second,
                Net:     "udp",
        }

        // Create TLS client for DNS over TLS support
        tlsClient := &dns.Client{
                Timeout: time.Duration(timeout) * time.Second,
                Net:     "tcp-tls",
        }

        // Test the resolver
        if !p.testResolver(address, client) {
                p.logger.Printf("Resolver test failed: %s", address)
                return nil
        }

        return &DNSResolver{
                Address:   address,
                Client:    client,
                TLSClient: tlsClient,
                Statistics: ResolverStats{},
        }
}

// testResolver performs a basic connectivity test
func (p *ResolverPool) testResolver(address string, client *dns.Client) bool {
        msg := &dns.Msg{}
        msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        _, _, err := client.ExchangeContext(ctx, msg, address)
        return err == nil
}

// GetResolver returns the next available resolver using round-robin
func (p *ResolverPool) GetResolver() *DNSResolver {
        p.mutex.Lock()
        defer p.mutex.Unlock()

        if len(p.resolvers) == 0 {
                return nil
        }

        resolver := p.resolvers[p.index]
        p.index = (p.index + 1) % len(p.resolvers)
        return resolver
}

// GetBestResolver returns the resolver with the best performance statistics
func (p *ResolverPool) GetBestResolver() *DNSResolver {
        p.mutex.RLock()
        defer p.mutex.RUnlock()

        if len(p.resolvers) == 0 {
                return nil
        }

        var bestResolver *DNSResolver
        var bestScore float64

        for _, resolver := range p.resolvers {
                resolver.Statistics.mutex.RLock()
                score := p.calculateResolverScore(resolver)
                resolver.Statistics.mutex.RUnlock()

                if bestResolver == nil || score > bestScore {
                        bestResolver = resolver
                        bestScore = score
                }
        }

        return bestResolver
}

// calculateResolverScore calculates a performance score for a resolver
func (p *ResolverPool) calculateResolverScore(resolver *DNSResolver) float64 {
        stats := &resolver.Statistics

        if stats.Queries == 0 {
                return 1.0 // New resolver gets benefit of doubt
        }

        successRate := float64(stats.Successes) / float64(stats.Queries)
        avgTimeMs := float64(stats.AvgTime.Milliseconds())

        // Score based on success rate and response time
        // Higher success rate and lower response time = higher score
        score := successRate * (1000.0 / (avgTimeMs + 1.0))

        return score
}

// GetRandomResolver returns a random resolver from the pool
func (p *ResolverPool) GetRandomResolver() *DNSResolver {
        p.mutex.RLock()
        defer p.mutex.RUnlock()

        if len(p.resolvers) == 0 {
                return nil
        }

        index := rand.Intn(len(p.resolvers))
        return p.resolvers[index]
}

// GetResolverCount returns the number of available resolvers
func (p *ResolverPool) GetResolverCount() int {
        p.mutex.RLock()
        defer p.mutex.RUnlock()
        return len(p.resolvers)
}

// GetResolverStats returns statistics for all resolvers
func (p *ResolverPool) GetResolverStats() map[string]ResolverStats {
        p.mutex.RLock()
        defer p.mutex.RUnlock()

        stats := make(map[string]ResolverStats)
        for _, resolver := range p.resolvers {
                resolver.Statistics.mutex.RLock()
                stats[resolver.Address] = resolver.Statistics
                resolver.Statistics.mutex.RUnlock()
        }

        return stats
}

// Close cleans up the resolver pool
func (p *ResolverPool) Close() {
        p.mutex.Lock()
        defer p.mutex.Unlock()
        p.resolvers = nil
        p.logger.Println("Resolver pool closed")
}

// ExchangeContext performs a DNS query with context support and statistics tracking
func (r *DNSResolver) ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
        r.Statistics.mutex.Lock()
        r.Statistics.Queries++
        r.Statistics.mutex.Unlock()

        response, rtt, err := r.Client.ExchangeContext(ctx, msg, address)

        r.Statistics.mutex.Lock()
        if err != nil {
                r.Statistics.Failures++
        } else {
                r.Statistics.Successes++
                // Update average response time
                if r.Statistics.AvgTime == 0 {
                        r.Statistics.AvgTime = rtt
                } else {
                        r.Statistics.AvgTime = (r.Statistics.AvgTime + rtt) / 2
                }
        }
        r.Statistics.mutex.Unlock()

        return response, rtt, err
}

// ExchangeContextTLS performs a DNS query over TLS
func (r *DNSResolver) ExchangeContextTLS(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
        r.Statistics.mutex.Lock()
        r.Statistics.Queries++
        r.Statistics.mutex.Unlock()

        response, rtt, err := r.TLSClient.ExchangeContext(ctx, msg, address)

        r.Statistics.mutex.Lock()
        if err != nil {
                r.Statistics.Failures++
        } else {
                r.Statistics.Successes++
                if r.Statistics.AvgTime == 0 {
                        r.Statistics.AvgTime = rtt
                } else {
                        r.Statistics.AvgTime = (r.Statistics.AvgTime + rtt) / 2
                }
        }
        r.Statistics.mutex.Unlock()

        return response, rtt, err
}

// loadResolversFromFile loads resolver addresses from a file
func loadResolversFromFile(filename string) ([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open resolvers file: %v", err)
        }
        defer file.Close()

        var resolvers []string
        scanner := bufio.NewScanner(file)

        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        resolvers = append(resolvers, line)
                }
        }

        if err := scanner.Err(); err != nil {
                return nil, fmt.Errorf("error reading resolvers file: %v", err)
        }

        return resolvers, nil
}

// DNSResult represents the result of a DNS query with security information
type DNSResult struct {
        Domain          string
        Type            uint16
        Response        *dns.Msg
        Error           error
        Resolver        string
        SecurityInfo    *SecurityInfo
        ProtocolSupport *ProtocolSupport
        SecurityScore   *SecurityScore
}

// SecurityInfo contains security-related information about a DNS response
type SecurityInfo struct {
        DNSSECValid     bool
        DNSSECPresent   bool
        ValidationError error
        Chain           []*dns.RR
}

// ProtocolSupport contains information about supported security protocols
type ProtocolSupport struct {
        DoH        bool // DNS over HTTPS
        DoT        bool // DNS over TLS
        DNSSEC     bool
        HTTPSRedirect bool
}

// SecurityScore contains the calculated security score for a domain
type SecurityScore struct {
        Overall     int // 0-100
        DNSSEC      int
        TLS         int
        Certificate int
        Details     map[string]interface{}
}
