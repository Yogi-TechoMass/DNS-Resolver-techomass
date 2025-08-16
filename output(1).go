package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// OutputHandler manages different output formats for DNS results
type OutputHandler struct {
	file       *os.File
	format     string
	logger     *log.Logger
	csvWriter  *csv.Writer
	jsonOutput bool
	firstJSON  bool
}

// NewOutputHandler creates a new output handler
func NewOutputHandler(outputFile, format string, logger *log.Logger) *OutputHandler {
	var file *os.File = os.Stdout

	if outputFile != "" {
		var err error
		file, err = os.Create(outputFile)
		if err != nil {
			logger.Fatalf("Failed to create output file: %v", err)
		}
	}

	handler := &OutputHandler{
		file:      file,
		format:    format,
		logger:    logger,
		firstJSON: true,
	}

	// Initialize format-specific handlers
	switch format {
	case "csv":
		handler.csvWriter = csv.NewWriter(file)
		handler.writeCSVHeader()
	case "json":
		handler.jsonOutput = true
		fmt.Fprint(file, "[\n")
	}

	return handler
}

// WriteResult writes a DNS result in the specified format
func (oh *OutputHandler) WriteResult(result *DNSResult) {
	switch oh.format {
	case "simple":
		oh.writeSimpleFormat(result)
	case "json":
		oh.writeJSONFormat(result)
	case "csv":
		oh.writeCSVFormat(result)
	default:
		oh.writeSimpleFormat(result)
	}
}

// writeSimpleFormat writes results in simple text format with security information
func (oh *OutputHandler) writeSimpleFormat(result *DNSResult) {
	if result.Error != nil {
		fmt.Fprintf(oh.file, "ERROR: %s - %v\n", result.Domain, result.Error)
		return
	}

	if result.Response == nil || len(result.Response.Answer) == 0 {
		fmt.Fprintf(oh.file, "NO ANSWER: %s\n", result.Domain)
		return
	}

	// Write basic DNS information
	for _, rr := range result.Response.Answer {
		fmt.Fprintf(oh.file, "%s\n", rr.String())
	}

	// Write security information if available
	if result.SecurityInfo != nil {
		oh.writeSecurityInfo(result)
	}

	// Write protocol support information
	if result.ProtocolSupport != nil {
		oh.writeProtocolInfo(result)
	}

	// Write security score
	if result.SecurityScore != nil {
		oh.writeSecurityScore(result)
	}

	fmt.Fprint(oh.file, "\n")
}

// writeSecurityInfo writes security information in simple format
func (oh *OutputHandler) writeSecurityInfo(result *DNSResult) {
	secInfo := result.SecurityInfo
	fmt.Fprintf(oh.file, "  Security Status:\n")
	
	if secInfo.DNSSECPresent {
		if secInfo.DNSSECValid {
			fmt.Fprintf(oh.file, "    DNSSEC: ✓ Valid\n")
		} else {
			fmt.Fprintf(oh.file, "    DNSSEC: ✗ Invalid")
			if secInfo.ValidationError != nil {
				fmt.Fprintf(oh.file, " (%v)", secInfo.ValidationError)
			}
			fmt.Fprint(oh.file, "\n")
		}
	} else {
		fmt.Fprintf(oh.file, "    DNSSEC: ✗ Not present\n")
	}

	if len(secInfo.Chain) > 0 {
		fmt.Fprintf(oh.file, "    DNSSEC Chain: %d records\n", len(secInfo.Chain))
	}
}

// writeProtocolInfo writes protocol support information
func (oh *OutputHandler) writeProtocolInfo(result *DNSResult) {
	protocols := result.ProtocolSupport
	fmt.Fprintf(oh.file, "  Protocol Support:\n")
	
	fmt.Fprintf(oh.file, "    DoH (DNS over HTTPS): %s\n", oh.boolToStatus(protocols.DoH))
	fmt.Fprintf(oh.file, "    DoT (DNS over TLS): %s\n", oh.boolToStatus(protocols.DoT))
	fmt.Fprintf(oh.file, "    HTTPS Redirect: %s\n", oh.boolToStatus(protocols.HTTPSRedirect))
}

// writeSecurityScore writes security score information
func (oh *OutputHandler) writeSecurityScore(result *DNSResult) {
	score := result.SecurityScore
	fmt.Fprintf(oh.file, "  Security Score:\n")
	fmt.Fprintf(oh.file, "    Overall: %d/100 (Grade: %s)\n", 
		score.Overall, oh.getSecurityGrade(score.Overall))
	fmt.Fprintf(oh.file, "    DNSSEC: %d/30\n", score.DNSSEC)
	fmt.Fprintf(oh.file, "    TLS/Protocols: %d/35\n", score.TLS)
	fmt.Fprintf(oh.file, "    Certificate: %d/35\n", score.Certificate)
}

// writeJSONFormat writes results in JSON format
func (oh *OutputHandler) writeJSONFormat(result *DNSResult) {
	jsonResult := oh.convertToJSONResult(result)

	if !oh.firstJSON {
		fmt.Fprint(oh.file, ",\n")
	} else {
		oh.firstJSON = false
	}

	jsonData, err := json.MarshalIndent(jsonResult, "  ", "  ")
	if err != nil {
		oh.logger.Printf("Error marshaling JSON: %v", err)
		return
	}

	fmt.Fprintf(oh.file, "  %s", string(jsonData))
}

// convertToJSONResult converts DNSResult to a JSON-friendly structure
func (oh *OutputHandler) convertToJSONResult(result *DNSResult) map[string]interface{} {
	jsonResult := map[string]interface{}{
		"domain":    result.Domain,
		"type":      dns.TypeToString[result.Type],
		"resolver":  result.Resolver,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if result.Error != nil {
		jsonResult["error"] = result.Error.Error()
		jsonResult["status"] = "error"
		return jsonResult
	}

	if result.Response == nil || len(result.Response.Answer) == 0 {
		jsonResult["status"] = "no_answer"
		return jsonResult
	}

	jsonResult["status"] = "success"

	// Convert DNS answers
	var answers []map[string]interface{}
	for _, rr := range result.Response.Answer {
		answer := map[string]interface{}{
			"name":  rr.Header().Name,
			"type":  dns.TypeToString[rr.Header().Rrtype],
			"class": dns.ClassToString[rr.Header().Class],
			"ttl":   rr.Header().Ttl,
			"data":  oh.extractRRData(rr),
		}
		answers = append(answers, answer)
	}
	jsonResult["answers"] = answers

	// Add security information
	if result.SecurityInfo != nil {
		jsonResult["security"] = oh.convertSecurityInfoToJSON(result.SecurityInfo)
	}

	// Add protocol support information
	if result.ProtocolSupport != nil {
		jsonResult["protocols"] = map[string]interface{}{
			"doh":            result.ProtocolSupport.DoH,
			"dot":            result.ProtocolSupport.DoT,
			"dnssec":         result.ProtocolSupport.DNSSEC,
			"https_redirect": result.ProtocolSupport.HTTPSRedirect,
		}
	}

	// Add security score
	if result.SecurityScore != nil {
		jsonResult["security_score"] = map[string]interface{}{
			"overall":     result.SecurityScore.Overall,
			"grade":       oh.getSecurityGrade(result.SecurityScore.Overall),
			"dnssec":      result.SecurityScore.DNSSEC,
			"tls":         result.SecurityScore.TLS,
			"certificate": result.SecurityScore.Certificate,
			"details":     result.SecurityScore.Details,
		}
	}

	return jsonResult
}

// convertSecurityInfoToJSON converts SecurityInfo to JSON
func (oh *OutputHandler) convertSecurityInfoToJSON(secInfo *SecurityInfo) map[string]interface{} {
	security := map[string]interface{}{
		"dnssec_present": secInfo.DNSSECPresent,
		"dnssec_valid":   secInfo.DNSSECValid,
	}

	if secInfo.ValidationError != nil {
		security["validation_error"] = secInfo.ValidationError.Error()
	}

	if len(secInfo.Chain) > 0 {
		security["chain_length"] = len(secInfo.Chain)
	}

	return security
}

// writeCSVFormat writes results in CSV format
func (oh *OutputHandler) writeCSVFormat(result *DNSResult) {
	if result.Error != nil {
		oh.csvWriter.Write([]string{
			result.Domain,
			dns.TypeToString[result.Type],
			"ERROR",
			result.Error.Error(),
			"", "", "", "", "", "", "", "", "", "",
		})
		oh.csvWriter.Flush()
		return
	}

	if result.Response == nil || len(result.Response.Answer) == 0 {
		oh.csvWriter.Write([]string{
			result.Domain,
			dns.TypeToString[result.Type],
			"NO_ANSWER",
			"", "", "", "", "", "", "", "", "", "", "",
		})
		oh.csvWriter.Flush()
		return
	}

	for _, rr := range result.Response.Answer {
		record := []string{
			result.Domain,
			dns.TypeToString[result.Type],
			"SUCCESS",
			rr.Header().Name,
			dns.TypeToString[rr.Header().Rrtype],
			strconv.Itoa(int(rr.Header().Ttl)),
			oh.extractRRData(rr),
			result.Resolver,
		}

		// Add security information
		if result.SecurityInfo != nil {
			record = append(record,
				oh.boolToString(result.SecurityInfo.DNSSECPresent),
				oh.boolToString(result.SecurityInfo.DNSSECValid),
			)
		} else {
			record = append(record, "", "")
		}

		// Add protocol information
		if result.ProtocolSupport != nil {
			record = append(record,
				oh.boolToString(result.ProtocolSupport.DoH),
				oh.boolToString(result.ProtocolSupport.DoT),
				oh.boolToString(result.ProtocolSupport.HTTPSRedirect),
			)
		} else {
			record = append(record, "", "", "")
		}

		// Add security score
		if result.SecurityScore != nil {
			record = append(record, strconv.Itoa(result.SecurityScore.Overall))
		} else {
			record = append(record, "")
		}

		oh.csvWriter.Write(record)
	}

	oh.csvWriter.Flush()
}

// writeCSVHeader writes the CSV header
func (oh *OutputHandler) writeCSVHeader() {
	header := []string{
		"Domain", "QueryType", "Status", "Name", "Type", "TTL", "Data", "Resolver",
		"DNSSEC_Present", "DNSSEC_Valid", "DoH_Support", "DoT_Support", 
		"HTTPS_Redirect", "Security_Score",
	}
	oh.csvWriter.Write(header)
	oh.csvWriter.Flush()
}

// extractRRData extracts the data portion from a resource record
func (oh *OutputHandler) extractRRData(rr dns.RR) string {
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// boolToStatus converts boolean to status string
func (oh *OutputHandler) boolToStatus(b bool) string {
	if b {
		return "✓ Supported"
	}
	return "✗ Not supported"
}

// boolToString converts boolean to string
func (oh *OutputHandler) boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// getSecurityGrade converts numerical score to letter grade
func (oh *OutputHandler) getSecurityGrade(score int) string {
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

// Close closes the output handler and finalizes output
func (oh *OutputHandler) Close() {
	if oh.jsonOutput {
		fmt.Fprint(oh.file, "\n]\n")
	}

	if oh.csvWriter != nil {
		oh.csvWriter.Flush()
	}

	if oh.file != os.Stdout {
		oh.file.Close()
	}
}
