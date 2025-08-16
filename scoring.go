package main

import (
        "log"
        "strings"
)

// SecurityScorer calculates security scores for domains
type SecurityScorer struct {
        logger *log.Logger
}

// NewSecurityScorer creates a new security scorer
func NewSecurityScorer(logger *log.Logger) *SecurityScorer {
        return &SecurityScorer{
                logger: logger,
        }
}

// CalculateScore calculates a comprehensive security score for a DNS result
func (ss *SecurityScorer) CalculateScore(result *DNSResult) *SecurityScore {
        score := &SecurityScore{
                Overall:     0,
                DNSSEC:      0,
                TLS:         0,
                Certificate: 0,
                Details:     make(map[string]interface{}),
        }

        // Calculate DNSSEC score
        score.DNSSEC = ss.calculateDNSSECScore(result)

        // Calculate TLS/Protocol score
        score.TLS = ss.calculateTLSScore(result)

        // Calculate Certificate score
        score.Certificate = ss.calculateCertificateScore(result)

        // Calculate overall score (weighted average)
        score.Overall = ss.calculateOverallScore(score)

        // Add detailed scoring information
        ss.addScoringDetails(score, result)

        return score
}

// calculateDNSSECScore calculates the DNSSEC-related security score
func (ss *SecurityScorer) calculateDNSSECScore(result *DNSResult) int {
        score := 0
        maxScore := 30

        if result.SecurityInfo == nil {
                return score
        }

        secInfo := result.SecurityInfo

        // DNSSEC presence adds points
        if secInfo.DNSSECPresent {
                score += 15
                ss.logger.Printf("DNSSEC present for %s: +15 points", result.Domain)
        }

        // Valid DNSSEC adds more points
        if secInfo.DNSSECValid {
                score += 15
                ss.logger.Printf("DNSSEC valid for %s: +15 points", result.Domain)
        } else if secInfo.DNSSECPresent {
                // DNSSEC present but invalid - subtract points
                score -= 5
                ss.logger.Printf("DNSSEC invalid for %s: -5 points", result.Domain)
        }

        // Bonus for complete DNSSEC chain
        if len(secInfo.Chain) > 0 {
                score += minInt(5, len(secInfo.Chain))
                ss.logger.Printf("DNSSEC chain for %s: +%d points", result.Domain, minInt(5, len(secInfo.Chain)))
        }

        return minInt(maxScore, maxInt(0, score))
}

// calculateTLSScore calculates the TLS/Protocol-related security score
func (ss *SecurityScorer) calculateTLSScore(result *DNSResult) int {
        score := 0
        maxScore := 35

        if result.ProtocolSupport == nil {
                return score
        }

        protocols := result.ProtocolSupport

        // DNS over HTTPS support
        if protocols.DoH {
                score += 15
                ss.logger.Printf("DoH support for %s: +15 points", result.Domain)
        }

        // DNS over TLS support
        if protocols.DoT {
                score += 15
                ss.logger.Printf("DoT support for %s: +15 points", result.Domain)
        }

        // HTTPS redirect
        if protocols.HTTPSRedirect {
                score += 5
                ss.logger.Printf("HTTPS redirect for %s: +5 points", result.Domain)
        }

        return minInt(maxScore, score)
}

// calculateCertificateScore calculates the certificate-related security score
func (ss *SecurityScorer) calculateCertificateScore(result *DNSResult) int {
        score := 0
        maxScore := 35

        // This is a placeholder for certificate validation
        // In a full implementation, you would:
        // 1. Retrieve and validate SSL certificates
        // 2. Check certificate transparency logs
        // 3. Validate certificate chain
        // 4. Check for proper certificate configuration

        // For now, we'll use some heuristics based on domain characteristics
        domain := strings.ToLower(result.Domain)

        // Well-known secure domains get bonus points
        if ss.isWellKnownSecureDomain(domain) {
                score += 20
                ss.logger.Printf("Well-known secure domain %s: +20 points", result.Domain)
        }

        // Domains with security-focused TLDs
        if ss.hasSecurityTLD(domain) {
                score += 10
                ss.logger.Printf("Security-focused TLD for %s: +10 points", result.Domain)
        }

        // Penalty for known insecure patterns
        if ss.hasInsecurePatterns(domain) {
                score -= 10
                ss.logger.Printf("Insecure patterns in %s: -10 points", result.Domain)
        }

        return minInt(maxScore, maxInt(0, score))
}

// calculateOverallScore calculates the weighted overall security score
func (ss *SecurityScorer) calculateOverallScore(score *SecurityScore) int {
        // Weighted calculation:
        // DNSSEC: 30% weight
        // TLS/Protocols: 35% weight  
        // Certificate: 35% weight

        weighted := float64(score.DNSSEC)*0.30 + 
                                float64(score.TLS)*0.35 + 
                                float64(score.Certificate)*0.35

        return int(weighted)
}

// addScoringDetails adds detailed scoring information
func (ss *SecurityScorer) addScoringDetails(score *SecurityScore, result *DNSResult) {
        details := score.Details

        // Add DNSSEC details
        details["dnssec_present"] = result.SecurityInfo != nil && result.SecurityInfo.DNSSECPresent
        details["dnssec_valid"] = result.SecurityInfo != nil && result.SecurityInfo.DNSSECValid
        
        if result.SecurityInfo != nil && result.SecurityInfo.ValidationError != nil {
                details["dnssec_error"] = result.SecurityInfo.ValidationError.Error()
        }

        // Add protocol details
        if result.ProtocolSupport != nil {
                details["doh_support"] = result.ProtocolSupport.DoH
                details["dot_support"] = result.ProtocolSupport.DoT
                details["https_redirect"] = result.ProtocolSupport.HTTPSRedirect
        }

        // Add scoring rationale
        details["scoring_rationale"] = ss.generateScoringRationale(score, result)
}

// generateScoringRationale generates a human-readable scoring explanation
func (ss *SecurityScorer) generateScoringRationale(score *SecurityScore, result *DNSResult) string {
        var rationale []string

        // DNSSEC rationale
        if score.DNSSEC > 20 {
                rationale = append(rationale, "Strong DNSSEC implementation")
        } else if score.DNSSEC > 10 {
                rationale = append(rationale, "Partial DNSSEC implementation")
        } else {
                rationale = append(rationale, "No or weak DNSSEC implementation")
        }

        // TLS rationale
        if score.TLS > 25 {
                rationale = append(rationale, "Excellent protocol security support")
        } else if score.TLS > 15 {
                rationale = append(rationale, "Good protocol security support")
        } else {
                rationale = append(rationale, "Limited protocol security support")
        }

        // Certificate rationale
        if score.Certificate > 25 {
                rationale = append(rationale, "Strong certificate security")
        } else if score.Certificate > 15 {
                rationale = append(rationale, "Moderate certificate security")
        } else {
                rationale = append(rationale, "Weak certificate security")
        }

        return strings.Join(rationale, "; ")
}

// isWellKnownSecureDomain checks if a domain is known to be security-focused
func (ss *SecurityScorer) isWellKnownSecureDomain(domain string) bool {
        secureDomains := map[string]bool{
                "google.com":        true,
                "cloudflare.com":    true,
                "microsoft.com":     true,
                "amazon.com":        true,
                "github.com":        true,
                "stackoverflow.com": true,
                "mozilla.org":       true,
                "eff.org":          true,
                "letsencrypt.org":  true,
                "certificate-transparency.org": true,
        }

        // Check exact match
        if secureDomains[domain] {
                return true
        }

        // Check if it's a subdomain of a secure domain
        for secureDomain := range secureDomains {
                if strings.HasSuffix(domain, "."+secureDomain) {
                        return true
                }
        }

        return false
}

// hasSecurityTLD checks if domain has a security-focused top-level domain
func (ss *SecurityScorer) hasSecurityTLD(domain string) bool {
        securityTLDs := []string{
                ".security",
                ".secure",
                ".trust",
                ".bank",
                ".insurance",
                ".gov",
                ".mil",
                ".edu",
        }

        for _, tld := range securityTLDs {
                if strings.HasSuffix(domain, tld) {
                        return true
                }
        }

        return false
}

// hasInsecurePatterns checks for patterns that might indicate security issues
func (ss *SecurityScorer) hasInsecurePatterns(domain string) bool {
        insecurePatterns := []string{
                "test",
                "staging",
                "dev",
                "demo",
                "temp",
                "temporary",
                "insecure",
                "unsafe",
                "nossl",
                "unencrypted",
        }

        domainLower := strings.ToLower(domain)
        
        for _, pattern := range insecurePatterns {
                if strings.Contains(domainLower, pattern) {
                        return true
                }
        }

        return false
}

// GetSecurityGrade converts numerical score to letter grade
func (ss *SecurityScorer) GetSecurityGrade(score int) string {
        switch {
        case score >= 90:
                return "A+"
        case score >= 80:
                return "A"
        case score >= 70:
                return "B"
        case score >= 60:
                return "C"
        case score >= 50:
                return "D"
        default:
                return "F"
        }
}

// GetRecommendations provides security improvement recommendations
func (ss *SecurityScorer) GetRecommendations(score *SecurityScore, result *DNSResult) []string {
        var recommendations []string

        // DNSSEC recommendations
        if score.DNSSEC < 15 {
                recommendations = append(recommendations, "Implement DNSSEC to ensure DNS integrity and authenticity")
        } else if score.DNSSEC < 25 {
                recommendations = append(recommendations, "Review and fix DNSSEC configuration issues")
        }

        // Protocol recommendations
        if score.TLS < 20 {
                recommendations = append(recommendations, "Implement DNS over HTTPS (DoH) and DNS over TLS (DoT)")
        }

        // Certificate recommendations
        if score.Certificate < 20 {
                recommendations = append(recommendations, "Improve SSL/TLS certificate configuration and validation")
        }

        // Overall recommendations
        if score.Overall < 70 {
                recommendations = append(recommendations, "Consider comprehensive security audit and improvement plan")
        }

        return recommendations
}




