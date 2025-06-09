package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ================= VIRUS TOTAL
type ThreatResultVT struct {
	VendorName string
	Category   string
}

type AnalysisStatVT struct {
	StatMalicious        int
	StatSuspicious       int
	StatUndetected       int
	StatHarmless         int
	StatTimeout          int
	StatConfirmedTimeout int
	StatFailure          int
	StatTypeUnsupported  int
}

type ScanResultVT struct {
	Owner         string
	Country       string
	AnalysisStats AnalysisStatVT
	Score         string
}

func ParseVirusTotalResponse(respBody io.Reader) (*ScanResultVT, error) {
	var responseData map[string]interface{}
	if err := json.NewDecoder(respBody).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, ok := responseData["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: data field missing")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: attributes field missing")
	}

	lastAnalysisResults, ok := attributes["last_analysis_results"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format: last_analysis_results field missing")
	}

	var threatResults []ThreatResultVT
	for vendorName, vendorResultRaw := range lastAnalysisResults {
		vendorResult, ok := vendorResultRaw.(map[string]interface{})
		if !ok {
			continue
		}

		category, ok := vendorResult["category"].(string)
		if !ok {
			continue
		}

		if category == "suspicious" || category == "malicious" {
			threatResults = append(threatResults, ThreatResultVT{
				VendorName: vendorName,
				Category:   category,
			})
		}
	}

	var asn string
	if asnRaw, ok := attributes["asn"]; ok {
		switch v := asnRaw.(type) {
		case string:
			asn = v
		case float64:
			asn = fmt.Sprintf("%v", v)
		}
	}

	if asn == "" {
		asn = "Unknown"
	}

	asOwner := "Unknown"
	if asOwnerRaw, ok := attributes["as_owner"]; ok && asOwnerRaw != nil {
		asOwner, _ = asOwnerRaw.(string)
	}

	country := "Unknown"
	if countryRaw, ok := attributes["country"]; ok && countryRaw != nil {
		country, _ = countryRaw.(string)
	}

	// Konversi map ke struct AnalysisStatVT
	var analysisStats AnalysisStatVT
	if statsRaw, ok := attributes["last_analysis_stats"].(map[string]interface{}); ok {
		// Ekstrak masing-masing field statistik
		if malicious, exists := statsRaw["malicious"]; exists {
			switch v := malicious.(type) {
			case float64:
				analysisStats.StatMalicious = int(v)
			case int:
				analysisStats.StatMalicious = v
			}
		}

		if suspicious, exists := statsRaw["suspicious"]; exists {
			switch v := suspicious.(type) {
			case float64:
				analysisStats.StatSuspicious = int(v)
			case int:
				analysisStats.StatSuspicious = v
			}
		}

		if undetected, exists := statsRaw["undetected"]; exists {
			switch v := undetected.(type) {
			case float64:
				analysisStats.StatUndetected = int(v)
			case int:
				analysisStats.StatUndetected = v
			}
		}

		if harmless, exists := statsRaw["harmless"]; exists {
			switch v := harmless.(type) {
			case float64:
				analysisStats.StatHarmless = int(v)
			case int:
				analysisStats.StatHarmless = v
			}
		}

		if timeout, exists := statsRaw["timeout"]; exists {
			switch v := timeout.(type) {
			case float64:
				analysisStats.StatTimeout = int(v)
			case int:
				analysisStats.StatTimeout = v
			}
		}

		if confirmedTimeout, exists := statsRaw["confirmed-timeout"]; exists {
			switch v := confirmedTimeout.(type) {
			case float64:
				analysisStats.StatConfirmedTimeout = int(v)
			case int:
				analysisStats.StatConfirmedTimeout = v
			}
		}

		if failure, exists := statsRaw["failure"]; exists {
			switch v := failure.(type) {
			case float64:
				analysisStats.StatFailure = int(v)
			case int:
				analysisStats.StatFailure = v
			}
		}

		if typeUnsupported, exists := statsRaw["type-unsupported"]; exists {
			switch v := typeUnsupported.(type) {
			case float64:
				analysisStats.StatTypeUnsupported = int(v)
			case int:
				analysisStats.StatTypeUnsupported = v
			}
		}
	}

	maliciousCount := 0
	for _, result := range threatResults {
		if result.Category == "malicious" {
			maliciousCount++
		}
	}

	scanResult := &ScanResultVT{
		Owner:         fmt.Sprintf("%s %s", asn, asOwner),
		Country:       country,
		AnalysisStats: analysisStats,
		Score:         fmt.Sprintf("%d/%d", maliciousCount, len(lastAnalysisResults)),
	}

	// 	CORE IDENTIFICATION FIELDS
	// - Target: The hash, IP, or domain being examined, identifies the subject of analysis
	// - ScanType: Type of scan ("hash", "ip", or "domain"), categorizes for filtering
	// - ScanTime: Timestamp when scan was performed, for temporal analysis and correlation

	// OWNERSHIP INFORMATION
	// - Owner: Network operator or ASN owner, identifies who controls the resource
	// - Country: Geographic location of the resource, important for risk assessment

	// DETECTION METRICS
	// - Score: Ratio of malicious detections to total scanners (e.g., "52/75"), key risk indicator
	// - StatMalicious: Number of engines that flagged the target as malicious
	// - StatSuspicious: Number of engines that flagged the target as suspicious but not confirmed malicious
	// - StatUndetected: Number of engines that did not detect any threats
	// - StatHarmless: Number of engines that explicitly classified the target as harmless

	// ERROR METRICS
	// - StatTimeout: Number of engines that timed out during analysis
	// - StatConfirmedTimeout: Number of confirmed timeouts, distinct from general timeouts
	// - StatFailure: Number of engines that failed to analyze the target
	// - StatTypeUnsupported: Number of engines that don't support the target type

	return scanResult, nil
}

// ================ ABUSEIPDB
type AbuseIPDBResponse struct {
	Data AbuseIPDBData `json:"data"`
}
type AbuseIPDBReport struct {
	ReportedAt          string   `json:"reportedAt"`
	Comment             string   `json:"comment"`
	ReporterId          int      `json:"reporterId"`
	ReporterCountryCode string   `json:"reporterCountryCode"`
	ReporterCountryName string   `json:"reporterCountryName"`
	Categories          []string `json:"categories"`
}

type AbuseIPDBData struct {
	IpAddress            string            `json:"ipAddress"`
	IsPublic             bool              `json:"isPublic"`
	IpVersion            int               `json:"ipVersion"`
	IsWhitelisted        bool              `json:"isWhitelisted"`
	AbuseConfidenceScore int               `json:"abuseConfidenceScore"`
	CountryCode          string            `json:"countryCode"`
	CountryName          string            `json:"countryName"`
	UsageType            string            `json:"usageType"`
	Isp                  string            `json:"isp"`
	Domain               string            `json:"domain"`
	Hostnames            []string          `json:"hostnames"`
	IsTor                bool              `json:"isTor"`
	TotalReports         int               `json:"totalReports"`
	NumDistinctUsers     int               `json:"numDistinctUsers"`
	LastReportedAt       string            `json:"lastReportedAt"`
	Reports              []AbuseIPDBReport `json:"reports"`
}

func ParseAbuseIPDBResponse(respBody io.Reader) (*AbuseIPDBData, error) {

	// 	CORE IDENTIFICATION FIELDS
	// - Target: The IP address being examined, identifies the subject of analysis
	// - ScanType: Always "ip" for AbuseIPDB, categorizes the scan type
	// - ScanTime: Timestamp when scan was performed, important for temporal context

	// PUBLIC NETWORK INFORMATION
	// - IsPublic: Whether the IP is publicly routable (true/false)
	// - CountryName: Geographic location (country code and name), helps identify origin
	// - UsageType: Category of IP usage (e.g., "Fixed Line ISP", "Data Center"), contextualizes risk
	// - ISP: Internet Service Provider managing the IP, helps identify network responsibility
	// - Domain: Primary domain associated with the IP, provides organizational context

	// ABUSE METRICS
	// - AbuseConfidenceScore: 0-100 score indicating confidence that IP is abusive
	// - TotalReports: Total number of abuse reports submitted for this IP
	// - NumDistinctUsers: Number of unique users who reported abuse, validates report credibility
	// - LastReportedAt: Timestamp of most recent abuse report, indicates recency of activity

	// TRUST INDICATORS
	// - IsWhitelisted: Whether IP is on AbuseIPDB's whitelist of trusted IPs (true/false)

	var response AbuseIPDBResponse
	if err := json.NewDecoder(respBody).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Data.IpAddress == "" {
		return nil, fmt.Errorf("invalid response format: ipAddress field missing")
	}

	return &response.Data, nil
}

// ================= HYBRID ANALYSIS
type HybridAnalysisData struct {
	SHA512            string   `json:"sha512"`
	SHA256            string   `json:"sha256"`
	SHA1              string   `json:"sha1"`
	MD5               string   `json:"md5"`
	ThreatScore       int      `json:"threat_score"`
	ThreatLevel       int      `json:"threat_level"`
	Verdict           string   `json:"verdict"`
	VXFamily          string   `json:"vx_family"`
	AVDetect          int      `json:"av_detect"`
	AnalysisStartTime string   `json:"analysis_start_time"`
	EnvironmentDesc   string   `json:"environment_desscription"`
	TypeShort         []string `json:"type_short"`
	Tags              []string `json:"tags"`
	TotalProcesses    int      `json:"total_processes"`
	TotalSignatures   int      `json:"total_signatures"`
	TotalNetworkConns int      `json:"total_network_connections"`
}

type HybridAnalysisResponse []HybridAnalysisData

// ScanResultHA represents the parsed data from Hybrid Analysis response
type ScanResultHA struct {
	SHA512       string // SHA512 is not used in Hybrid Analysis, but included for consistency
	SHA256       string
	SHA1         string
	MD5          string
	ThreatScore  int
	ThreatLevel  int
	Verdict      string
	VXFamily     string
	AVDetect     int
	AnalysisTime string
	Environment  string
	FileType     string // Joined from TypeShort
	Tags         string // Joined from Tags
	Processes    int
	Signatures   int
	NetworkConns int
}

func ParseSingleHybridAnalysisResponse(respBody io.Reader) (*ScanResultHA, error) {
	var response HybridAnalysisResponse
	if err := json.NewDecoder(respBody).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("invalid response format: empty response")
	}

	// Use the first result from the array
	data := response[0]

	if data.SHA256 == "" {
		return nil, fmt.Errorf("invalid response format: sha256 field missing")
	}

	// Convert array fields to strings
	fileType := "unknown"
	if len(data.TypeShort) > 0 {
		fileType = strings.Join(data.TypeShort, ",")
	}

	tags := ""
	if len(data.Tags) > 0 {
		tags = strings.Join(data.Tags, ",")
	}

	// Create structured result
	// 	CORE IDENTIFICATION FIELDS
	// - Target: The file hash being examined, identifies the subject of analysis
	// - ScanType: Always "hash" for HybridAnalysis scans
	// - ScanTime: Timestamp when scan was performed, for temporal reference

	// FILE IDENTIFICATION
	// - SHA512: 512-bit hash of the file, provides strong cryptographic identification
	// - SHA256: 256-bit hash, most commonly used for malware identification
	// - SHA1: 160-bit hash, older standard still used for compatibility
	// - MD5: 128-bit hash, least secure but widely used for legacy systems

	// THREAT ASSESSMENT
	// - ThreatScore: Numerical risk assessment (higher is more risky)
	// - ThreatLevel: Categorized risk level (0-2, with 2 being highest risk)
	// - Verdict: Classification result (e.g., "malicious", "no specific threat")
	// - VXFamily: Malware family name if identified (e.g., "Trojan.Ransom.Ryuk")
	// - AVDetect: Percentage or count of AV engines detecting the file as malicious

	// ANALYSIS CONTEXT
	// - AnalysisTime: When the file was analyzed by Hybrid Analysis
	// - Environment: Environment where analysis was performed
	// - FileType: Type of file identified, important for context (e.g., "peexe,64bits,executable")
	// - Tags: Classification tags applied to the sample (e.g., "tag,viruscheck,eicar")

	// BEHAVIORAL INDICATORS
	// - Processes: Number of processes created during dynamic analysis
	// - Signatures: Number of malicious signatures matched
	// - NetworkConnections: Number of network connections established during analysis
	scanResult := &ScanResultHA{
		SHA512:       data.SHA512,
		SHA256:       data.SHA256,
		SHA1:         data.SHA1,
		MD5:          data.MD5,
		ThreatScore:  data.ThreatScore,
		ThreatLevel:  data.ThreatLevel,
		Verdict:      data.Verdict,
		VXFamily:     data.VXFamily,
		AVDetect:     data.AVDetect,
		AnalysisTime: data.AnalysisStartTime,
		Environment:  data.EnvironmentDesc,
		FileType:     fileType,
		Tags:         tags,
		Processes:    data.TotalProcesses,
		Signatures:   data.TotalSignatures,
		NetworkConns: data.TotalNetworkConns,
	}

	return scanResult, nil
}

// ================ IP QUALITY SCORE
type IPQSData struct {
	Success           bool     `json:"success"`
	Message           string   `json:"message"`
	FraudScore        int      `json:"fraud_score"`
	CountryCode       string   `json:"country_code"`
	Region            string   `json:"region"`
	City              string   `json:"city"`
	ISP               string   `json:"ISP"`
	Organization      string   `json:"organization"`
	ASN               int      `json:"ASN"`
	Host              string   `json:"host"`
	ConnectionType    string   `json:"connection_type"`
	Proxy             bool     `json:"proxy"`
	VPN               bool     `json:"vpn"`
	Tor               bool     `json:"tor"`
	RecentAbuse       bool     `json:"recent_abuse"`
	FrequentAbuser    bool     `json:"frequent_abuser"`
	AbuseVelocity     string   `json:"abuse_velocity"`
	BotStatus         bool     `json:"bot_status"`
	SecurityScanner   bool     `json:"security_scanner"`
	SharedConnection  bool     `json:"shared_connection"`
	DynamicConnection bool     `json:"dynamic_connection"`
	TrustedNetwork    bool     `json:"trusted_network"`
	RiskFactors       []string `json:"risk_factors,omitempty"`
	UserAgent         string   `json:"user_agent,omitempty"`
	OperatingSystem   string   `json:"operating_system,omitempty"`
	Browser           string   `json:"browser,omitempty"`
	DeviceModel       string   `json:"device_model,omitempty"`
	DeviceBrand       string   `json:"device_brand,omitempty"`
	RequestID         string   `json:"request_id"`
}

// ScanResultIPQS represents the parsed data for CSV output
type ScanResultIPQS struct {
	FraudScore       int
	CountryCode      string
	ISP              string
	ConnectionType   string
	Proxy            bool
	VPN              bool
	Tor              bool
	RecentAbuse      bool
	AbuseVelocity    string
	BotStatus        bool
	SecurityScanner  bool
	SharedConnection bool
	TrustedNetwork   bool
	OperatingSystem  string
	Browser          string
	RiskFlags        string // Joined list of key risk factors
}

func ParseIPQSResponse(respBody io.Reader) (*ScanResultIPQS, error) {
	var responseData IPQSData
	if err := json.NewDecoder(respBody).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !responseData.Success {
		return nil, fmt.Errorf("IPQS API error: %s", responseData.Message)
	}

	// Create structured result
	// 	CORE IDENTIFICATION FIELDS
	// - Target: The IP address being examined, used to identify the subject of analysis
	// - ScanType: Always "ip" for IPQS scans, categorizes the scan type for filtering
	// - ScanTime: Timestamp when scan was performed, important for temporal analysis and event correlation

	// RISK ASSESSMENT FIELDS
	// - FraudScore: Risk score 0-100, IPQS's primary metric, higher values = higher risk
	// - RecentAbuse: Indicates whether the IP has been recently involved in abuse
	// - AbuseVelocity: Rate of abuse reports ("low", "medium", "high")
	// - RiskFlags: Specific detailed reasons why the IP is flagged as risky

	// NETWORK IDENTITY FIELDS
	// - CountryCode: Two-letter country code (US, ID, etc.), geographic origin can indicate risk
	// - ISP: Internet Service Provider, identifies the network operator
	// - ConnectionType: Type of internet connection, different risk profiles (Residential typically safer vs Data Center)

	// ANONYMIZING TECHNOLOGY FIELDS
	// - Proxy: Whether IP is known to be a proxy, can be used to mask true origin
	// - VPN: Whether IP belongs to a VPN service, often used to hide identity
	// - Tor: Whether IP is a Tor exit node, commonly used for anonymous browsing

	// BEHAVIORAL INDICATORS
	// - BotStatus: Shows bot-like behavior, indicates automated activity vs human
	// - SecurityScanner: IP known to scan for vulnerabilities, indicates reconnaissance activity
	// - SharedConnection: IP shared among multiple users, makes attribution more difficult
	// - TrustedNetwork: Whether IP originates from a trusted network

	// DEVICE INFORMATION
	// - OperatingSystem: OS being used, may indicate spoofing if unusual
	// - Browser: Browser being used, may reveal fingerprinting attempts
	scanResult := &ScanResultIPQS{
		FraudScore:       responseData.FraudScore,
		CountryCode:      responseData.CountryCode,
		ISP:              responseData.ISP,
		ConnectionType:   responseData.ConnectionType,
		Proxy:            responseData.Proxy,
		VPN:              responseData.VPN,
		Tor:              responseData.Tor,
		RecentAbuse:      responseData.RecentAbuse,
		AbuseVelocity:    responseData.AbuseVelocity,
		BotStatus:        responseData.BotStatus,
		SecurityScanner:  responseData.SecurityScanner,
		SharedConnection: responseData.SharedConnection,
		TrustedNetwork:   responseData.TrustedNetwork,
		OperatingSystem:  responseData.OperatingSystem,
		Browser:          responseData.Browser,
		RiskFlags:        strings.Join(responseData.RiskFactors, ","),
	}

	return scanResult, nil
}
