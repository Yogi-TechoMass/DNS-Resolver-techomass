package main

import (
        "context"
        "sync"
        "time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
        tokens   chan struct{}
        ticker   *time.Ticker
        qps      int
        mutex    sync.RWMutex
        stopped  bool
        stopChan chan struct{}
}

// NewRateLimiter creates a new rate limiter with specified queries per second
func NewRateLimiter(qps int) *RateLimiter {
        if qps <= 0 {
                qps = 100 // Default QPS
        }

        rl := &RateLimiter{
                tokens:   make(chan struct{}, qps),
                qps:      qps,
                stopChan: make(chan struct{}),
        }

        // Fill initial tokens
        for i := 0; i < qps; i++ {
                select {
                case rl.tokens <- struct{}{}:
                default:
                        break
                }
        }

        // Start token refill goroutine
        interval := time.Second / time.Duration(qps)
        rl.ticker = time.NewTicker(interval)

        go rl.refillTokens()

        return rl
}

// refillTokens continuously refills the token bucket
func (rl *RateLimiter) refillTokens() {
        for {
                select {
                case <-rl.ticker.C:
                        select {
                        case rl.tokens <- struct{}{}:
                                // Token added successfully
                        default:
                                // Bucket is full, skip
                        }
                case <-rl.stopChan:
                        return
                }
        }
}

// Wait blocks until a token is available, respecting context cancellation
func (rl *RateLimiter) Wait(ctx context.Context) error {
        select {
        case <-rl.tokens:
                return nil
        case <-ctx.Done():
                return ctx.Err()
        }
}

// TryWait attempts to acquire a token without blocking
func (rl *RateLimiter) TryWait() bool {
        select {
        case <-rl.tokens:
                return true
        default:
                return false
        }
}

// SetQPS updates the queries per second rate
func (rl *RateLimiter) SetQPS(qps int) {
        if qps <= 0 {
                return
        }

        rl.mutex.Lock()
        defer rl.mutex.Unlock()

        if rl.stopped {
                return
        }

        // Stop current ticker
        rl.ticker.Stop()

        // Update QPS
        oldQPS := rl.qps
        rl.qps = qps

        // Adjust token bucket size
        if qps > oldQPS {
                // Add more tokens for increased rate
                diff := qps - oldQPS
                for i := 0; i < diff; i++ {
                        select {
                        case rl.tokens <- struct{}{}:
                        default:
                                break
                        }
                }
        } else if qps < oldQPS {
                // Remove excess tokens for decreased rate
                diff := oldQPS - qps
                for i := 0; i < diff; i++ {
                        select {
                        case <-rl.tokens:
                        default:
                                break
                        }
                }
        }

        // Start new ticker with updated interval
        interval := time.Second / time.Duration(qps)
        rl.ticker = time.NewTicker(interval)
}

// GetQPS returns the current queries per second setting
func (rl *RateLimiter) GetQPS() int {
        rl.mutex.RLock()
        defer rl.mutex.RUnlock()
        return rl.qps
}

// GetAvailableTokens returns the number of available tokens
func (rl *RateLimiter) GetAvailableTokens() int {
        return len(rl.tokens)
}

// Stop stops the rate limiter and cleans up resources
func (rl *RateLimiter) Stop() {
        rl.mutex.Lock()
        defer rl.mutex.Unlock()

        if rl.stopped {
                return
        }

        rl.stopped = true
        close(rl.stopChan)
        
        if rl.ticker != nil {
                rl.ticker.Stop()
        }
}

// AdaptiveRateLimiter adjusts rate based on success/failure rates
type AdaptiveRateLimiter struct {
        *RateLimiter
        successCount   int64
        failureCount   int64
        lastAdjustment time.Time
        minQPS         int
        maxQPS         int
        adjustInterval time.Duration
        mutex          sync.RWMutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(initialQPS, minQPS, maxQPS int) *AdaptiveRateLimiter {
        if minQPS <= 0 {
                minQPS = 10
        }
        if maxQPS <= 0 {
                maxQPS = 1000
        }
        if initialQPS < minQPS {
                initialQPS = minQPS
        }
        if initialQPS > maxQPS {
                initialQPS = maxQPS
        }

        arl := &AdaptiveRateLimiter{
                RateLimiter:    NewRateLimiter(initialQPS),
                minQPS:         minQPS,
                maxQPS:         maxQPS,
                adjustInterval: 30 * time.Second,
                lastAdjustment: time.Now(),
        }

        go arl.adaptRate()

        return arl
}

// RecordSuccess records a successful operation
func (arl *AdaptiveRateLimiter) RecordSuccess() {
        arl.mutex.Lock()
        arl.successCount++
        arl.mutex.Unlock()
}

// RecordFailure records a failed operation
func (arl *AdaptiveRateLimiter) RecordFailure() {
        arl.mutex.Lock()
        arl.failureCount++
        arl.mutex.Unlock()
}

// adaptRate periodically adjusts the rate based on success/failure ratios
func (arl *AdaptiveRateLimiter) adaptRate() {
        ticker := time.NewTicker(arl.adjustInterval)
        defer ticker.Stop()

        for range ticker.C {
                arl.mutex.Lock()
                
                if arl.stopped {
                        arl.mutex.Unlock()
                        return
                }

                successCount := arl.successCount
                failureCount := arl.failureCount
                
                // Reset counters
                arl.successCount = 0
                arl.failureCount = 0
                
                arl.mutex.Unlock()

                total := successCount + failureCount
                if total == 0 {
                        continue
                }

                successRate := float64(successCount) / float64(total)
                currentQPS := arl.GetQPS()

                var newQPS int

                switch {
                case successRate > 0.95: // Very high success rate - increase rate
                        newQPS = minInt(currentQPS+int(float64(currentQPS)*0.1), arl.maxQPS)
                case successRate > 0.90: // High success rate - slightly increase rate
                        newQPS = minInt(currentQPS+int(float64(currentQPS)*0.05), arl.maxQPS)
                case successRate < 0.70: // Low success rate - decrease rate significantly
                        newQPS = maxInt(currentQPS-int(float64(currentQPS)*0.2), arl.minQPS)
                case successRate < 0.85: // Medium success rate - slightly decrease rate
                        newQPS = maxInt(currentQPS-int(float64(currentQPS)*0.1), arl.minQPS)
                default: // Good success rate - maintain current rate
                        newQPS = currentQPS
                }

                if newQPS != currentQPS {
                        arl.SetQPS(newQPS)
                }
        }
}

// GetStatistics returns current rate limiter statistics
func (arl *AdaptiveRateLimiter) GetStatistics() map[string]interface{} {
        arl.mutex.RLock()
        defer arl.mutex.RUnlock()

        total := arl.successCount + arl.failureCount
        var successRate float64
        if total > 0 {
                successRate = float64(arl.successCount) / float64(total)
        }

        return map[string]interface{}{
                "current_qps":    arl.GetQPS(),
                "min_qps":        arl.minQPS,
                "max_qps":        arl.maxQPS,
                "success_count":  arl.successCount,
                "failure_count":  arl.failureCount,
                "success_rate":   successRate,
                "available_tokens": arl.GetAvailableTokens(),
        }
}

// Helper functions for AdaptiveRateLimiter
func minInt(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func maxInt(a, b int) int {
        if a > b {
                return a
        }
        return b
}
