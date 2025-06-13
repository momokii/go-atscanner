# Go-ATScanner

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)

A comprehensive threat intelligence scanner for IPs, domains, and file hashes, integrating multiple security APIs into one unified tool.

## 🔍 Features

- **Multiple Security APIs**: Integrates VirusTotal, AbuseIPDB, Hybrid Analysis, and IPQualityScore
- **Support for Different Target Types**:
  - IP addresses (VirusTotal, AbuseIPDB, IPQualityScore)
  - Domains (VirusTotal)
  - File Hashes (VirusTotal, Hybrid Analysis)
- **Batch Processing**: Scan multiple targets from CSV files
- **Detailed Reports**: Export results as CSV files for further analysis
- **AI-Powered Analysis**: LLM-based analysis of scan results with structured security reports
- **Multiple Report Formats**: Export professional reports in both TXT and PDF formats
- **User-Friendly Interface**: Simple command-line interface with interactive selection

## 📋 Supported Services

| Service | Target Types | Description | Free Tier API Limits |
|---------|-------------|-------------|----------------|
| VirusTotal | IP, Hash, Domain | Comprehensive threat intelligence platform | 4 requests/min, 500 requests/day |
| AbuseIPDB | IP | IP address abuse database | 1,000 requests/day |
| Hybrid Analysis | Hash | Advanced malware analysis | 100 requests/day |
| IPQualityScore | IP | Fraud prevention and risk scoring | 35 requests/d |

## 🚀 Installation

### Prerequisites
- Go 1.21 or higher
- API keys for each service you wish to use

### Building from Source

```bash
# Clone the repository
git clone https://github.com/momokii/go-atscanner.git

# Navigate to project directory
cd go-atscanner

# Build the project
go build -o go-atscanner.exe
```

## ⚙️ Configuration

Create a `.env` file in the project root with your API keys:

```
# Security Scanner API Keys
VIRUS_TOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
HYBRID_ANALYSIS_API_KEY=your_hybridanalysis_api_key
IPQS_API_KEY=your_ipqualityscore_api_key

# LLM API Key for AI-Powered Analysis (Optional)
OPENAI_API_KEY=your_openai_api_key
```

## 📊 Usage

### Prepare Target List

Create a CSV file in the `targets` directory with your targets with filename `targets.csv`:

```
example.com
192.168.1.1
44d88612fea8a8f36de82e1278abb02f
```

### Run the Scanner

```bash
# Run the application
./go-atscanner.exe
```

Follow the interactive prompts:

1. Select a security API to use (VirusTotal, AbuseIPDB, Hybrid Analysis, or IPQualityScore)
2. Choose whether to manually input your API key or use the one from your `.env` file
3. Decide if you want to use LLM-powered analysis for generating comprehensive reports
4. If you select LLM analysis, provide your OpenAI API key if not in the `.env` file

The scanner will process all targets from your CSV file and generate the appropriate reports.

### View Results

Results are saved in the following formats:

**CSV Results** (Raw Data):
- `results/results-virustotal.csv`
- `results/results-abuseipdb.csv`
- `results/results-hybridanalysis.csv`
- `results/results-ipqs.csv`

**LLM Analysis Reports** (when LLM analysis is enabled):
- `results/reports/report-virustotal.txt` (Text format)
- `results/reports/report-abuseipdb.txt` (Text format)
- `results/reports/report-hybridanalysis.txt` (Text format)
- `results/reports/report-ipqs.txt` (Text format)
- `results/reports/report-virustotal.pdf` (PDF format)
- `results/reports/report-abuseipdb.pdf` (PDF format)
- `results/reports/report-hybridanalysis.pdf` (PDF format)
- `results/reports/report-ipqs.pdf` (PDF format)

## 📑 Understanding Results

Each scanner provides different insights:

### VirusTotal Results
```
// Explanation of values in each VirusTotal Scanner field

/*
CORE IDENTIFICATION FIELDS
- Target: The hash, IP, or domain being examined, identifies the subject of analysis
- ScanType: Type of scan ("hash", "ip", or "domain"), categorizes for filtering
- ScanTime: Timestamp when scan was performed, for temporal analysis and correlation

OWNERSHIP INFORMATION
- Owner: Network operator or ASN owner, identifies who controls the resource
- Country: Geographic location of the resource, important for risk assessment

DETECTION METRICS
- Score: Ratio of malicious detections to total scanners (e.g., "52/75"), key risk indicator
- StatMalicious: Number of engines that flagged the target as malicious
- StatSuspicious: Number of engines that flagged the target as suspicious but not confirmed malicious
- StatUndetected: Number of engines that did not detect any threats
- StatHarmless: Number of engines that explicitly classified the target as harmless

ERROR METRICS
- StatTimeout: Number of engines that timed out during analysis
- StatConfirmedTimeout: Number of confirmed timeouts, distinct from general timeouts
- StatFailure: Number of engines that failed to analyze the target
- StatTypeUnsupported: Number of engines that don't support the target type
*/
```

### AbuseIPDB Results
```
// Explanation of values in each AbuseIPDB Scanner field

/*
CORE IDENTIFICATION FIELDS
- Target: The IP address being examined, identifies the subject of analysis
- ScanType: Always "ip" for AbuseIPDB, categorizes the scan type
- ScanTime: Timestamp when scan was performed, important for temporal context

PUBLIC NETWORK INFORMATION
- IsPublic: Whether the IP is publicly routable (true/false)
- CountryName: Geographic location (country code and name), helps identify origin
- UsageType: Category of IP usage (e.g., "Fixed Line ISP", "Data Center"), contextualizes risk
- ISP: Internet Service Provider managing the IP, helps identify network responsibility
- Domain: Primary domain associated with the IP, provides organizational context

ABUSE METRICS
- AbuseConfidenceScore: 0-100 score indicating confidence that IP is abusive
- TotalReports: Total number of abuse reports submitted for this IP
- NumDistinctUsers: Number of unique users who reported abuse, validates report credibility
- LastReportedAt: Timestamp of most recent abuse report, indicates recency of activity

TRUST INDICATORS
- IsWhitelisted: Whether IP is on AbuseIPDB's whitelist of trusted IPs (true/false)
*/
```

### Hybrid Analysis Results
```
// Explanation of values in each HybridAnalysis Scanner field

/*
CORE IDENTIFICATION FIELDS
- Target: The file hash being examined, identifies the subject of analysis
- ScanType: Always "hash" for HybridAnalysis scans
- ScanTime: Timestamp when scan was performed, for temporal reference

FILE IDENTIFICATION
- SHA512: 512-bit hash of the file, provides strong cryptographic identification
- SHA256: 256-bit hash, most commonly used for malware identification
- SHA1: 160-bit hash, older standard still used for compatibility
- MD5: 128-bit hash, least secure but widely used for legacy systems

THREAT ASSESSMENT
- ThreatScore: Numerical risk assessment (higher is more risky)
- ThreatLevel: Categorized risk level (0-2, with 2 being highest risk)
- Verdict: Classification result (e.g., "malicious", "no specific threat")
- VXFamily: Malware family name if identified (e.g., "Trojan.Ransom.Ryuk")
- AVDetect: Percentage or count of AV engines detecting the file as malicious

ANALYSIS CONTEXT
- AnalysisTime: When the file was analyzed by Hybrid Analysis
- Environment: Environment where analysis was performed
- FileType: Type of file identified, important for context (e.g., "peexe,64bits,executable")
- Tags: Classification tags applied to the sample (e.g., "tag,viruscheck,eicar")

BEHAVIORAL INDICATORS
- Processes: Number of processes created during dynamic analysis
- Signatures: Number of malicious signatures matched
- NetworkConnections: Number of network connections established during analysis
*/
```

### IPQualityScore Results
```
// Explanation of values in each IPQS Scanner field

/*
CORE IDENTIFICATION FIELDS
- Target: The IP address being examined, used to identify the subject of analysis
- ScanType: Always "ip" for IPQS scans, categorizes the scan type for filtering
- ScanTime: Timestamp when scan was performed, important for temporal analysis and event correlation

RISK ASSESSMENT FIELDS
- FraudScore: Risk score 0-100, IPQS's primary metric, higher values = higher risk
- RecentAbuse: Indicates whether the IP has been recently involved in abuse
- AbuseVelocity: Rate of abuse reports ("low", "medium", "high")
- RiskFlags: Specific detailed reasons why the IP is flagged as risky

NETWORK IDENTITY FIELDS
- CountryCode: Two-letter country code (US, ID, etc.), geographic origin can indicate risk
- ISP: Internet Service Provider, identifies the network operator
- ConnectionType: Type of internet connection, different risk profiles (Residential typically safer vs Data Center)

ANONYMIZING TECHNOLOGY FIELDS
- Proxy: Whether IP is known to be a proxy, can be used to mask true origin
- VPN: Whether IP belongs to a VPN service, often used to hide identity
- Tor: Whether IP is a Tor exit node, commonly used for anonymous browsing

BEHAVIORAL INDICATORS
- BotStatus: Shows bot-like behavior, indicates automated activity vs human
- SecurityScanner: IP known to scan for vulnerabilities, indicates reconnaissance activity
- SharedConnection: IP shared among multiple users, makes attribution more difficult
- TrustedNetwork: Whether IP originates from a trusted network

DEVICE INFORMATION
- OperatingSystem: OS being used, may indicate spoofing if unusual
- Browser: Browser being used, may reveal fingerprinting attempts
*/
```

## 🧠 LLM-Powered Analysis

Go-ATScanner now features AI-powered analysis of scan results. The tool can:

- Generate comprehensive security assessment reports for each scanner type
- Analyze and interpret technical data into actionable intelligence
- Provide structured, professional-grade security reports with:
  - Executive summary with clear threat level assessment
  - Detailed threat analysis with risk scoring
  - Key security indicators extracted from scan data
  - Technical details explaining findings
  - Actionable recommendations based on scan results

### Enabling LLM Analysis

To use the LLM analysis feature:

1. Add your OpenAI API key to the `.env` file:
   ```
   OPENAI_API_KEY=your_openai_api_key
   ```

2. When running the scanner, select "yes" when prompted to use LLM for report generation
3. Reports are saved in the `results/reports` directory in both TXT and PDF formats:
   - `results/reports/report-virustotal.txt`
   - `results/reports/report-abuseipdb.txt`
   - `results/reports/report-hybridanalysis.txt`
   - `results/reports/report-ipqs.txt`

## 📝 Future Enhancements

Future enhancements planned for this project:
- [ ] Interactive visualizations for scan results
- [ ] Automated threat correlation across multiple sources
- [ ] Expanded support for additional security APIs
- [ ] Custom report templates for different organizational needs
