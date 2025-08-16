package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Stats tracks various statistics for DNS resolution operations
type Stats struct {
	mutex sync.RWMutex

	// Basic counters
	total       int64
	processed   int64
	successful  int64
	errors      int64
	noAnswer    int64
	wildcards   int64

	// Security-related counters
	dnssecValid   int64
	dnssecInvalid int64
	dohSupport    int64
	dotSupport    int64

	// Timing statistics
	startTime   time.Time
	avgResponse time.Duration
	minResponse time.Duration
	maxResponse time.Duration

	// Performance metrics
	queriesPerSecond float64
	peakQPS          float64

	// Error breakdown
	timeouts        int64
	networkErrors   int64
	validationErrors int64
	otherErrors     int64

	// Security scores
	securityScores []int
	avgSecurityScore float64
}

// NewStats creates a new statistics tracker
func NewStats() *Stats {
	return &Stats{
		startTime:   time.Now(),
		minResponse: time.Hour, // Initialize to a large value
	}
}

// IncrementTotal increments the total count
func (s *Stats) IncrementTotal() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.total++
}

// IncrementProcessed increments the processed count
func (s *Stats) IncrementProcessed() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.processed++
}

// IncrementSuccessful increments the successful count
func (s *Stats) IncrementSuccessful() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.successful++
}

// IncrementErrors increments the error count
func (s *Stats) IncrementErrors() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.errors++
}

// IncrementNoAnswer increments the no answer count
func (s *Stats) IncrementNoAnswer() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.noAnswer++
}

// IncrementWildcards increments the wildcard count
func (s *Stats) IncrementWildcards() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.wildcards++
}

// IncrementDNSSECValid increments the valid DNSSEC count
func (s *Stats) IncrementDNSSECValid() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.dnssecValid++
}

// IncrementDNSSECInvalid increments the invalid DNSSEC count
func (s *Stats) IncrementDNSSECInvalid() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.dnssecInvalid++
}

// IncrementDoHSupport increments the DoH support count
func (s *Stats) IncrementDoHSupport() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.dohSupport++
}

// IncrementDoTSupport increments the DoT support count
func (s *Stats) IncrementDoTSupport() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.dotSupport++
}

// RecordResponseTime records a response time and updates timing statistics
func (s *Stats) RecordResponseTime(duration time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update min/max response times
	if duration < s.minResponse {
		s.minResponse = duration
	}
	if duration > s.maxResponse {
		s.maxResponse = duration
	}

	// Calculate running average
	if s.avgResponse == 0 {
		s.avgResponse = duration
	} else {
		s.avgResponse = (s.avgResponse + duration) / 2
	}
}

// RecordSecurityScore records a security score
func (s *Stats) RecordSecurityScore(score int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.securityScores = append(s.securityScores, score)
	
	// Calculate running average
	total := 0
	for _, sc := range s.securityScores {
		total += sc
	}
	s.avgSecurityScore = float64(total) / float64(len(s.securityScores))
}

// RecordError records specific types of errors
func (s *Stats) RecordError(errorType string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	switch errorType {
	case "timeout":
		s.timeouts++
	case "network":
		s.networkErrors++
	case "validation":
		s.validationErrors++
	default:
		s.otherErrors++
	}
}

// GetTotal returns the total count
func (s *Stats) GetTotal() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.total
}

// GetProcessed returns the processed count
func (s *Stats) GetProcessed() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.processed
}

// GetSuccessful returns the successful count
func (s *Stats) GetSuccessful() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.successful
}

// GetErrors returns the error count
func (s *Stats) GetErrors() int64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.errors
}

// GetSuccessRate returns the success rate as a percentage
func (s *Stats) GetSuccessRate() float64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.processed == 0 {
		return 0.0
	}
	return (float64(s.successful) / float64(s.processed)) * 100.0
}

// GetQueriesPerSecond calculates the current queries per second
func (s *Stats) GetQueriesPerSecond() float64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	elapsed := time.Since(s.startTime).Seconds()
	if elapsed == 0 {
		return 0.0
	}

	qps := float64(s.processed) / elapsed
	
	// Update peak QPS
	if qps > s.peakQPS {
		s.peakQPS = qps
	}

	return qps
}

// GetDetailedStats returns detailed statistics
func (s *Stats) GetDetailedStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	elapsed := time.Since(s.startTime)
	qps := s.GetQueriesPerSecond()

	return map[string]interface{}{
		"runtime": map[string]interface{}{
			"elapsed_seconds": elapsed.Seconds(),
			"start_time":      s.startTime.Format(time.RFC3339),
		},
		"counters": map[string]interface{}{
			"total":      s.total,
			"processed":  s.processed,
			"successful": s.successful,
			"errors":     s.errors,
			"no_answer":  s.noAnswer,
			"wildcards":  s.wildcards,
		},
		"security": map[string]interface{}{
			"dnssec_valid":        s.dnssecValid,
			"dnssec_invalid":      s.dnssecInvalid,
			"doh_support":         s.dohSupport,
			"dot_support":         s.dotSupport,
			"avg_security_score":  s.avgSecurityScore,
			"total_scored_domains": len(s.securityScores),
		},
		"performance": map[string]interface{}{
			"queries_per_second": qps,
			"peak_qps":          s.peakQPS,
			"success_rate":      s.GetSuccessRate(),
		},
		"timing": map[string]interface{}{
			"avg_response_ms": s.avgResponse.Milliseconds(),
			"min_response_ms": s.minResponse.Milliseconds(),
			"max_response_ms": s.maxResponse.Milliseconds(),
		},
		"errors": map[string]interface{}{
			"timeouts":         s.timeouts,
			"network_errors":   s.networkErrors,
			"validation_errors": s.validationErrors,
			"other_errors":     s.otherErrors,
		},
	}
}

// StartReporter starts a background goroutine that periodically reports statistics
func (s *Stats) StartReporter(ctx context.Context, logger *log.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.PrintCurrentStats(logger)
		case <-ctx.Done():
			return
		}
	}
}

// PrintCurrentStats prints current statistics to the logger
func (s *Stats) PrintCurrentStats(logger *log.Logger) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	elapsed := time.Since(s.startTime)
	qps := s.GetQueriesPerSecond()
	successRate := s.GetSuccessRate()

	logger.Printf("Stats - Elapsed: %v, Processed: %d/%d, Success Rate: %.1f%%, QPS: %.1f",
		elapsed.Round(time.Second),
		s.processed,
		s.total,
		successRate,
		qps,
	)

	// Print security stats if available
	if s.dnssecValid > 0 || s.dnssecInvalid > 0 {
		logger.Printf("Security - DNSSEC Valid: %d, Invalid: %d, DoH: %d, DoT: %d, Avg Score: %.1f",
			s.dnssecValid,
			s.dnssecInvalid,
			s.dohSupport,
			s.dotSupport,
			s.avgSecurityScore,
		)
	}

	// Print error breakdown if there are errors
	if s.errors > 0 {
		logger.Printf("Errors - Timeouts: %d, Network: %d, Validation: %d, Other: %d",
			s.timeouts,
			s.networkErrors,
			s.validationErrors,
			s.otherErrors,
		)
	}
}

// PrintFinalStats prints final statistics summary
func (s *Stats) PrintFinalStats(logger *log.Logger) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	elapsed := time.Since(s.startTime)
	qps := float64(s.processed) / elapsed.Seconds()
	successRate := s.GetSuccessRate()

	logger.Println("=== Final Statistics ===")
	logger.Printf("Runtime: %v", elapsed.Round(time.Second))
	logger.Printf("Total domains: %d", s.total)
	logger.Printf("Processed: %d", s.processed)
	logger.Printf("Successful: %d", s.successful)
	logger.Printf("Errors: %d", s.errors)
	logger.Printf("No answer: %d", s.noAnswer)
	logger.Printf("Wildcards: %d", s.wildcards)
	logger.Printf("Success rate: %.1f%%", successRate)
	logger.Printf("Average QPS: %.1f", qps)
	logger.Printf("Peak QPS: %.1f", s.peakQPS)

	if s.avgResponse > 0 {
		logger.Printf("Response times - Avg: %v, Min: %v, Max: %v",
			s.avgResponse.Round(time.Millisecond),
			s.minResponse.Round(time.Millisecond),
			s.maxResponse.Round(time.Millisecond),
		)
	}

	// Security statistics
	if s.dnssecValid > 0 || s.dnssecInvalid > 0 || len(s.securityScores) > 0 {
		logger.Println("=== Security Statistics ===")
		logger.Printf("DNSSEC Valid: %d", s.dnssecValid)
		logger.Printf("DNSSEC Invalid: %d", s.dnssecInvalid)
		logger.Printf("DoH Support: %d", s.dohSupport)
		logger.Printf("DoT Support: %d", s.dotSupport)
		
		if len(s.securityScores) > 0 {
			logger.Printf("Domains scored: %d", len(s.securityScores))
			logger.Printf("Average security score: %.1f/100", s.avgSecurityScore)
		}
	}

	// Error breakdown
	if s.errors > 0 {
		logger.Println("=== Error Breakdown ===")
		logger.Printf("Timeouts: %d", s.timeouts)
		logger.Printf("Network errors: %d", s.networkErrors)
		logger.Printf("Validation errors: %d", s.validationErrors)
		logger.Printf("Other errors: %d", s.otherErrors)
	}

	logger.Println("=== End Statistics ===")
}

// Reset resets all statistics
func (s *Stats) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.total = 0
	s.processed = 0
	s.successful = 0
	s.errors = 0
	s.noAnswer = 0
	s.wildcards = 0
	s.dnssecValid = 0
	s.dnssecInvalid = 0
	s.dohSupport = 0
	s.dotSupport = 0
	s.timeouts = 0
	s.networkErrors = 0
	s.validationErrors = 0
	s.otherErrors = 0
	s.startTime = time.Now()
	s.avgResponse = 0
	s.minResponse = time.Hour
	s.maxResponse = 0
	s.queriesPerSecond = 0
	s.peakQPS = 0
	s.securityScores = nil
	s.avgSecurityScore = 0
}

// ExportCSV exports statistics to CSV format
func (s *Stats) ExportCSV() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return fmt.Sprintf("metric,value\n"+
		"total,%d\n"+
		"processed,%d\n"+
		"successful,%d\n"+
		"errors,%d\n"+
		"no_answer,%d\n"+
		"wildcards,%d\n"+
		"success_rate,%.2f\n"+
		"queries_per_second,%.2f\n"+
		"peak_qps,%.2f\n"+
		"avg_response_ms,%d\n"+
		"min_response_ms,%d\n"+
		"max_response_ms,%d\n"+
		"dnssec_valid,%d\n"+
		"dnssec_invalid,%d\n"+
		"doh_support,%d\n"+
		"dot_support,%d\n"+
		"avg_security_score,%.2f\n",
		s.total, s.processed, s.successful, s.errors, s.noAnswer, s.wildcards,
		s.GetSuccessRate(), s.GetQueriesPerSecond(), s.peakQPS,
		s.avgResponse.Milliseconds(), s.minResponse.Milliseconds(), s.maxResponse.Milliseconds(),
		s.dnssecValid, s.dnssecInvalid, s.dohSupport, s.dotSupport, s.avgSecurityScore,
	)
}
