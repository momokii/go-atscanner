package llm

import (
	"fmt"
	"os"
	"strings"

	"github.com/momokii/go-atscanner/pkg/utils"
	"github.com/momokii/go-llmbridge/pkg/openai"
)

var (
	OPENAI_API_KEY = os.Getenv("OPENAI_API_KEY")
)

type SummaryReportResponse struct {
	ExecutiveSummary string `json:"executive_summary"`
	ThreatAnalysis   string `json:"threat_analysis"`
	KeyIndicators    string `json:"key_indicators"`
	TechnicalDetails string `json:"technical_details"`
	Recommendations  string `json:"recommendations"`
}

const (
	// Common wrapper for all prompts to ensure consistent output format
	PROMPT_WRAPPER = `You are a cybersecurity analyst reviewing threat intelligence data. Your task is to analyze the provided scan results and create a comprehensive security assessment following EXACTLY this structure:

# Security Assessment Report: {serviceType}

## Executive Summary
A concise 3-sentence overview. First sentence states overall threat level (Low/Medium/High/Critical). Second sentence quantifies key findings (e.g., "X of Y samples were classified as malicious"). Third sentence summarizes the most significant security implication.

## Threat Analysis
**Overall Risk Level:** [Low/Medium/High/Critical]

**Risk Score:** [Numerical value if available, or N/A]

**Primary Concerns:**
* [First specific threat concern]
* [Second specific threat concern]
* [Third specific threat concern]

## Key Indicators
1. **[Indicator Name]**: [Precise value] - [One sentence explanation]
2. **[Indicator Name]**: [Precise value] - [One sentence explanation]
3. **[Indicator Name]**: [Precise value] - [One sentence explanation]
4. **[Indicator Name]**: [Precise value] - [One sentence explanation]
5. **[Indicator Name]**: [Precise value] - [One sentence explanation]

## Technical Details
**Detection Method:** [Method used]

**Classification:** [Malware type/Activity type]

**Technical Summary:**
[Technical explanation in exactly 3 sentences]

**Notable Artifacts:**
* [First artifact or behavior] - [Brief implication]
* [Second artifact or behavior] - [Brief implication]
* [Third artifact or behavior] - [Brief implication]

## Recommendations
1. **[Action Item]**: [One specific, actionable sentence]
2. **[Action Item]**: [One specific, actionable sentence]
3. **[Action Item]**: [One specific, actionable sentence]
4. **[Action Item]**: [One specific, actionable sentence]
5. **[Action Item]**: [One specific, actionable sentence]

You MUST follow this EXACT format without deviations. Do not add additional sections or modify the structure. Keep your analysis evidence-based, technically precise, and actionable.`
	// VirusTotal specific prompt
	PROMPT_VIRUSTOTAL = `${PROMPT_WRAPPER}

Analyze these VirusTotal scan results:
'''
{results}
'''

STRICTLY follow these guidelines for VirusTotal data:
- For "Overall Risk Level": If >50% engines detect it as malicious = Critical; 25-50% = High; 5-25% = Medium; <5% = Low
- For "Risk Score": Use the actual score ratio (e.g., "52/75")
- For "Key Indicators" ALWAYS include:
  1. Malicious detections count and percentage
  2. Suspicious detections count and percentage
  3. Detection consistency across engines
  4. Country of origin (for IPs/domains)
  5. Owner/ASN information (for IPs/domains)
- For hashes, the "Technical Summary" must identify the likely malware family/type
- For IPs/domains, analyze trustworthiness based on detection patterns

For "Recommendations" section, provide specific actions appropriate to the entity type:
- For malicious hashes: blocklisting, isolation, and removal steps
- For suspicious IPs: firewall rules, monitoring, or blocking recommendations
- For domains: DNS filtering or blocking suggestions`
	// AbuseIPDB specific prompt
	PROMPT_ABUSEIPDB = `${PROMPT_WRAPPER}

Analyze these AbuseIPDB scan results:
'''
{results}
'''

STRICTLY follow these guidelines for AbuseIPDB data:
- For "Overall Risk Level": AbuseConfidenceScore 0-25 = Low; 26-75 = Medium; 76-90 = High; 91-100 = Critical
- For "Risk Score": Use the actual AbuseConfidenceScore value (0-100)
- For "Key Indicators" ALWAYS include:
  1. Abuse confidence score (exact value)
  2. Total reports count
  3. Number of distinct reporting users
  4. Days since last reported abuse (calculated from LastReportedAt)
  5. Whitelist status (true/false)
- For "Technical Summary", categorize the likely abuse type based on:
  - IPs with scores >80 and many reports: likely dedicated to malicious activity
  - IPs with scores >50 but few reports: likely occasional abuse or false positives
  - IPs with scores <25 and few/no reports: likely benign
  
For "Recommendations" section, provide graduated responses based on risk level:
- For Critical risk: Immediate IP blocking at all network levels
- For High risk: Block at perimeter, investigate any historical connections
- For Medium risk: Implement monitoring and conditional blocking
- For Low risk: Regular monitoring only with no immediate action`
	// HybridAnalysis specific prompt
	PROMPT_HYBRIDANALYSIS = `${PROMPT_WRAPPER}

Analyze these Hybrid Analysis scan results:
'''
{results}
'''

STRICTLY follow these guidelines for Hybrid Analysis data:
- For "Overall Risk Level": ThreatLevel 0 = Low; 1 = Medium; 2 = High; verdict "malicious" = Critical
- For "Risk Score": Use the ThreatScore value if available, or AVDetect percentage
- For "Key Indicators" ALWAYS include:
  1. Threat level (numeric value)
  2. Verdict (exact classification)
  3. VX family (malware family if identified)
  4. AV detection percentage
  5. File type (executable, document, etc.)
- For "Technical Summary", include:
  1. File hash identification (SHA256 preferred)
  2. Malware classification and family
  3. Behavioral characteristics based on processes, signatures, and network connections
  
In "Notable Artifacts", list EXACTLY:
- Process behaviors (e.g., process count, injection techniques)
- Network activities (connection count, C2 servers)
- Notable tags and their security implications

For "Recommendations" section, provide malware-specific containment strategies:
- For ransomware: offline backup verification, network segmentation
- For trojans: credential rotation, persistent access removal
- For unknown malware: sandbox analysis, IOC extraction
- For all malicious verdicts: include specific file quarantine/deletion instructions`
	// IPQualityScore specific prompt
	PROMPT_IPQS = `${PROMPT_WRAPPER}

Analyze these IPQualityScore scan results:
'''
{results}
'''

STRICTLY follow these guidelines for IPQualityScore data:
- For "Overall Risk Level": FraudScore 0-25 = Low; 26-75 = Medium; 76-90 = High; 91-100 = Critical
- For "Risk Score": Use the exact FraudScore value (0-100)
- For "Key Indicators" ALWAYS include EXACTLY these 5 items:
  1. Fraud Score (exact value)
  2. Proxy/VPN/Tor status (true/false for each)
  3. Recent Abuse status (true/false)
  4. Bot Status (true/false)
  5. Connection Type (exact value)
- For "Technical Summary", classify the IP:
  1. Anonymizing proxy (if proxy/VPN/Tor is true)
  2. Automated threat (if bot status is true)
  3. Fraud originator (if fraud score > 75)
  4. Trusted network (if trusted_network is true)

In "Notable Artifacts", list EXACTLY:
- Anonymization methods detected (proxy, VPN, Tor)
- Behavioral red flags (recent abuse, bot activity)
- Network context (ISP reputation, connection type)

For "Recommendations" section, provide graduated responses based on fraud score:
- For scores >90: Block all traffic and investigate any past transactions
- For scores 75-90: Implement CAPTCHA and enhanced verification
- For scores 25-75: Apply risk-based authentication measures
- For proxies/VPNs: Specify whether to block, challenge, or allow with monitoring`
)

func CreateSummaryReport(serviceType utils.Servicetype, openaiClient openai.OpenAI) (string, error) {

	var basePrompt string

	switch serviceType {
	case utils.ServiceTypeVT:
		basePrompt = PROMPT_VIRUSTOTAL
	case utils.ServiceTypeAbuseIPDB:
		basePrompt = PROMPT_ABUSEIPDB
	case utils.ServiceTypeHybridAnalysis:
		basePrompt = PROMPT_HYBRIDANALYSIS
	case utils.ServiceTypeIPQS:
		basePrompt = PROMPT_IPQS
	default:
		return "", fmt.Errorf("unsupported service type: %s", serviceType)
	}

	// get result data
	result, err := utils.OpenCSVServiceResult(serviceType)
	if err != nil {
		return "", fmt.Errorf("failed to open CSV result file for service type %s: %w", serviceType, err)
	}

	// replace prompt
	prompt := strings.Replace(basePrompt, "${PROMPT_WRAPPER}", PROMPT_WRAPPER, 1)

	prompt = strings.Replace(prompt, "{serviceType}", string(serviceType), 1)

	prompt = strings.Replace(prompt, "{results}", result, 1)

	// LLM request
	message_summaries := []openai.OAMessageReq{
		{
			Role:    "user",
			Content: prompt,
		},
	}

	report_resp, err := openaiClient.OpenAIGetFirstContentDataResp(
		&message_summaries,
		false,
		nil,
		false,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get response from OpenAI: %w", err)
	}

	return report_resp.Content, nil
}
