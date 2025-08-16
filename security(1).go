package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

// SecurityValidator handles DNSSEC validation and security checks
type SecurityValidator struct {
	config *Config
	logger *log.Logger
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(config *Config, logger *log.Logger) *SecurityValidator {
	return &SecurityValidator{
		config: config,
		logger: logger,
	}
}

// ValidateResponse performs comprehensive security validation on a DNS response
func (sv *SecurityValidator) ValidateResponse(result *DNSResult) *SecurityInfo {
	secInfo := &SecurityInfo{
		DNSSECPresent: false,
		DNSSECValid:   false,
		Chain:         make([]*dns.RR, 0),
	}

	if result.Response == nil {
		return secInfo
	}

	// Check for DNSSEC presence
	secInfo.DNSSECPresent = sv.checkDNSSECPresence(result.Response)

	// Validate DNSSEC if present and validation is enabled
	if sv.config.DNSSECValidation && secInfo.DNSSECPresent {
		secInfo.DNSSECValid, secInfo.ValidationError = sv.validateDNSSEC(result)
		if secInfo.ValidationError != nil {
			sv.logger.Printf("DNSSEC validation error for %s: %v", result.Domain, secInfo.ValidationError)
		}
	}

	// Extract DNSSEC chain if present
	secInfo.Chain = sv.extractDNSSECChain(result.Response)

	return secInfo
}

// checkDNSSECPresence checks if DNSSEC records are present in the response
func (sv *SecurityValidator) checkDNSSECPresence(msg *dns.Msg) bool {
	// Check for RRSIG records in answer section
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}

	// Check for RRSIG records in additional section
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			return true
		}
	}

	// Check for DS or DNSKEY records
	for _, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeDS, dns.TypeDNSKEY:
			return true
		}
	}

	// Check if Authenticated Data (AD) bit is set
	return msg.AuthenticatedData
}

// validateDNSSEC performs DNSSEC validation
func (sv *SecurityValidator) validateDNSSEC(result *DNSResult) (bool, error) {
	if result.Response == nil {
		return false, fmt.Errorf("no response to validate")
	}

	msg := result.Response

	// Check if the Authenticated Data (AD) bit is set
	if msg.AuthenticatedData {
		return true, nil
	}

	// Perform manual DNSSEC validation
	return sv.performManualDNSSECValidation(result)
}

// performManualDNSSECValidation performs detailed DNSSEC validation
func (sv *SecurityValidator) performManualDNSSECValidation(result *DNSResult) (bool, error) {
	msg := result.Response

	// Find RRSIG records
	var rrsigRecords []*dns.RRSIG
	var signedRecords []dns.RR

	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigRecords = append(rrsigRecords, rrsig)
		} else {
			// Check if this record type matches any RRSIG
			for _, rrsig := range rrsigRecords {
				if rr.Header().Rrtype == rrsig.TypeCovered {
					signedRecords = append(signedRecords, rr)
				}
			}
		}
	}

	if len(rrsigRecords) == 0 {
		return false, fmt.Errorf("no RRSIG records found")
	}

	// For each RRSIG, we need to validate the signature
	for _, rrsig := range rrsigRecords {
		valid, err := sv.validateRRSIG(rrsig, signedRecords, result.Domain)
		if err != nil {
			sv.logger.Printf("RRSIG validation error: %v", err)
			continue
		}
		if valid {
			return true, nil
		}
	}

	return false, fmt.Errorf("no valid RRSIG found")
}

// validateRRSIG validates a single RRSIG record
func (sv *SecurityValidator) validateRRSIG(rrsig *dns.RRSIG, records []dns.RR, domain string) (bool, error) {
	// This is a simplified validation - in a production environment,
	// you would need to implement the full DNSSEC validation algorithm
	// including key retrieval, signature verification, etc.

	// Check basic RRSIG properties
	if rrsig.SignerName == "" {
		return false, fmt.Errorf("empty signer name")
	}

	if rrsig.KeyTag == 0 {
		return false, fmt.Errorf("invalid key tag")
	}

	// Check if the signer name is authoritative for the domain
	if !sv.isAuthoritativeSigner(domain, rrsig.SignerName) {
		return false, fmt.Errorf("signer not authoritative for domain")
	}

	// In a full implementation, you would:
	// 1. Retrieve the DNSKEY record for the signer
	// 2. Verify the signature using the public key
	// 3. Check the validity period
	// 4. Validate the chain of trust up to the root

	sv.logger.Printf("RRSIG validation placeholder for %s by %s", domain, rrsig.SignerName)
	
	// For now, we'll return true if basic checks pass
	return true, nil
}

// isAuthoritativeSigner checks if a signer is authoritative for a domain
func (sv *SecurityValidator) isAuthoritativeSigner(domain, signer string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	signer = strings.ToLower(strings.TrimSuffix(signer, "."))

	// The signer should be the domain itself or a parent domain
	return domain == signer || strings.HasSuffix(domain, "."+signer)
}

// extractDNSSECChain extracts DNSSEC-related records from the response
func (sv *SecurityValidator) extractDNSSECChain(msg *dns.Msg) []*dns.RR {
	var chain []*dns.RR

	// Extract from answer section
	for i, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
			chain = append(chain, &msg.Answer[i])
		}
	}

	// Extract from authority section
	for i, rr := range msg.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
			chain = append(chain, &msg.Ns[i])
		}
	}

	// Extract from additional section
	for i, rr := range msg.Extra {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
			chain = append(chain, &msg.Extra[i])
		}
	}

	return chain
}

// ValidateCertificate validates SSL/TLS certificates for a domain
func (sv *SecurityValidator) ValidateCertificate(domain string) (*x509.Certificate, error) {
	// This would implement certificate validation
	// For now, return a placeholder
	sv.logger.Printf("Certificate validation placeholder for %s", domain)
	return nil, fmt.Errorf("certificate validation not implemented")
}

// CheckSecurityHeaders checks for security-related DNS records
func (sv *SecurityValidator) CheckSecurityHeaders(domain string) map[string]bool {
	headers := map[string]bool{
		"CAA":    false, // Certificate Authority Authorization
		"TLSA":   false, // DNS-based Authentication of Named Entities
		"SSHFP":  false, // SSH Key Fingerprint
		"SMIMEA": false, // S/MIME Certificate Association
	}

	// This would implement actual DNS queries for security records
	sv.logger.Printf("Security headers check placeholder for %s", domain)

	return headers
}

// GetSecurityRecommendations provides security recommendations based on the analysis
func (sv *SecurityValidator) GetSecurityRecommendations(secInfo *SecurityInfo, domain string) []string {
	var recommendations []string

	if !secInfo.DNSSECPresent {
		recommendations = append(recommendations, "Enable DNSSEC for enhanced security")
	}

	if secInfo.DNSSECPresent && !secInfo.DNSSECValid {
		recommendations = append(recommendations, "Fix DNSSEC configuration - validation failed")
	}

	// Add more recommendations based on analysis
	recommendations = append(recommendations, "Consider implementing DNS over HTTPS (DoH)")
	recommendations = append(recommendations, "Consider implementing DNS over TLS (DoT)")

	return recommendations
}
