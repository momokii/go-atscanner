package utils

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

type Servicetype string

const (
	ServiceTypeVT             Servicetype = "virustotal"
	ServiceTypeAbuseIPDB      Servicetype = "abuseipdb"
	ServiceTypeHybridAnalysis Servicetype = "hybridanalysis"
	ServiceTypeIPQS           Servicetype = "ipqs"

	OUTPUT_DIR = "results"

	OUTPUT_DIR_REPORT_LLM = OUTPUT_DIR + "/reports"

	CSV_FILENAME_VT            = "results-virustotal.csv"
	CSV_RESULT_VT_FILEPATH     = OUTPUT_DIR + "/" + CSV_FILENAME_VT
	TXT_LLM_REPORT_VT_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-virustotal.txt"
	PDF_LLM_REPORT_VT_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-virustotal.pdf"

	CSV_FILENAME_ABUSEIPDB            = "results-abuseipdb.csv"
	CSV_RESULT_ABUSEIPDB_FILEPATH     = OUTPUT_DIR + "/" + CSV_FILENAME_ABUSEIPDB
	TXT_LLM_REPORT_ABUSEIPDB_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-abuseipdb.txt"
	PDF_LLM_REPORT_ABUSEIPDB_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-abuseipdb.pdf"

	CSV_FILENAME_HYBRIDANALYSIS            = "results-hybridanalysis.csv"
	CSV_RESULT_HYBRIDANALYSIS_FILEPATH     = OUTPUT_DIR + "/" + CSV_FILENAME_HYBRIDANALYSIS
	TXT_LLM_REPORT_HYBRIDANALYSIS_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-hybridanalysis.txt"
	PDF_LLM_REPORT_HYBRIDANALYSIS_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-hybridanalysis.pdf"

	CSV_FILENAME_IPQS            = "results-ipqs.csv"
	CSV_RESULT_IPQS_FILEPATH     = OUTPUT_DIR + "/" + CSV_FILENAME_IPQS
	TXT_LLM_REPORT_IPQS_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-ipqs.txt"
	PDF_LLM_REPORT_IPQS_FILEPATH = OUTPUT_DIR_REPORT_LLM + "/report-ipqs.pdf"
)

func SaveResultToCSV(scanType TargetType, target string, result interface{}, serviceType Servicetype) error {

	// create dir
	if err := os.MkdirAll(OUTPUT_DIR, 0755); err != nil {
		return err
	}

	// define csv path
	var csvResultPath string

	if serviceType == ServiceTypeVT {
		csvResultPath = CSV_RESULT_VT_FILEPATH
	} else if serviceType == ServiceTypeAbuseIPDB {
		csvResultPath = CSV_RESULT_ABUSEIPDB_FILEPATH
	} else if serviceType == ServiceTypeHybridAnalysis {
		csvResultPath = CSV_RESULT_HYBRIDANALYSIS_FILEPATH
	} else if serviceType == ServiceTypeIPQS {
		csvResultPath = CSV_RESULT_IPQS_FILEPATH
	} else {
		return fmt.Errorf("unsupported service type: %s", serviceType)
	}

	var headers, csvData []string

	// prepare data for CSV based on service type
	if serviceType == ServiceTypeVT {

		resultVT := result.(*ScanResultVT)

		csvData = []string{
			target,
			string(scanType),
			time.Now().Format(time.RFC3339),
			resultVT.Owner,
			resultVT.Country,
			resultVT.Score,
		}

		// prepare header
		headers = []string{
			"target",
			"scan_type",
			"scan_time",
			"owner",
			"country",
			"score",
			"stat_malicious",
			"stat_suspicious",
			"stat_undetected",
			"stat_harmless",
			"stat_timeout",
			"stat_confirmed-timeout",
			"stat_failure",
			"stat_type-unsupported",
		}

		csvData = append(csvData,
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatMalicious),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatSuspicious),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatUndetected),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatHarmless),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatTimeout),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatConfirmedTimeout),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatFailure),
			fmt.Sprintf("%d", resultVT.AnalysisStats.StatTypeUnsupported),
		)

	} else if serviceType == ServiceTypeAbuseIPDB {
		resultAbuseIPDB := result.(*AbuseIPDBData)
		resultData := resultAbuseIPDB

		csvData = []string{
			target,
			string(scanType),
			time.Now().Format(time.RFC3339),
			fmt.Sprintf("%t", resultData.IsPublic),
			fmt.Sprintf("%d", resultData.AbuseConfidenceScore),
			fmt.Sprintf("%s - %s", resultData.CountryCode, resultData.CountryName),
			resultData.UsageType,
			resultData.Isp,
			resultData.Domain,
			fmt.Sprintf("%d", resultData.TotalReports),
			fmt.Sprintf("%d", resultData.NumDistinctUsers),
			resultData.LastReportedAt,
			fmt.Sprintf("%t", resultData.IsWhitelisted),
		}

		// prepare header
		headers = []string{
			"target",
			"scan_type",
			"scan_time",
			"is_public",
			"abuse_confidence_score",
			"country_name",
			"usage_type",
			"isp",
			"domain",
			"total_reports",
			"num_distinct_users",
			"last_reported_at",
			"is_whitelisted",
		}

	} else if serviceType == ServiceTypeHybridAnalysis {

		resultHA := result.(*ScanResultHA)

		csvData = []string{
			target,
			string(scanType),
			time.Now().Format(time.RFC3339),
			resultHA.SHA512,
			resultHA.SHA256,
			resultHA.MD5,
			resultHA.SHA1,
			fmt.Sprintf("%d", resultHA.ThreatScore),
			fmt.Sprintf("%d", resultHA.ThreatLevel),
			resultHA.Verdict,
			resultHA.VXFamily,
			fmt.Sprintf("%d", resultHA.AVDetect),
			resultHA.AnalysisTime,
			resultHA.Environment,
			resultHA.FileType,
			resultHA.Tags,
			fmt.Sprintf("%d", resultHA.Processes),
			fmt.Sprintf("%d", resultHA.Signatures),
			fmt.Sprintf("%d", resultHA.NetworkConns),
		}

		headers = []string{
			"target",
			"scan_type",
			"scan_time",
			"sha512",
			"sha256",
			"sha1",
			"md5",
			"threat_score",
			"threat_level",
			"verdict",
			"vx_family",
			"av_detect",
			"analysis_time",
			"environment",
			"file_type",
			"tags",
			"processes",
			"signatures",
			"network_connections",
		}

	} else if serviceType == ServiceTypeIPQS {

		resultIPQS := result.(*ScanResultIPQS)

		csvData = []string{
			target,
			string(scanType),
			time.Now().Format(time.RFC3339),
			fmt.Sprintf("%d", resultIPQS.FraudScore),
			resultIPQS.CountryCode,
			resultIPQS.ISP,
			resultIPQS.ConnectionType,
			fmt.Sprintf("%t", resultIPQS.Proxy),
			fmt.Sprintf("%t", resultIPQS.VPN),
			fmt.Sprintf("%t", resultIPQS.Tor),
			fmt.Sprintf("%t", resultIPQS.RecentAbuse),
			resultIPQS.AbuseVelocity,
			fmt.Sprintf("%t", resultIPQS.BotStatus),
			fmt.Sprintf("%t", resultIPQS.SecurityScanner),
			fmt.Sprintf("%t", resultIPQS.SharedConnection),
			fmt.Sprintf("%t", resultIPQS.TrustedNetwork),
			resultIPQS.OperatingSystem,
			resultIPQS.Browser,
			resultIPQS.RiskFlags,
		}

		headers = []string{
			"target",
			"scan_type",
			"scan_time",
			"fraud_score",
			"country_code",
			"isp",
			"connection_type",
			"proxy",
			"vpn",
			"tor",
			"recent_abuse",
			"abuse_velocity",
			"bot_status",
			"security_scanner",
			"shared_connection",
			"trusted_network",
			"operating_system",
			"browser",
			"risk_flags",
		}

	}

	// Check if file exists and get existing content
	var existingRecords [][]string

	fileExists := false
	if _, err := os.Stat(csvResultPath); err == nil {
		fileInfo, err := os.Stat(csvResultPath)
		if err == nil && fileInfo.Size() > 0 {
			fileExists = true

			// Read existing file
			file, err := os.Open(csvResultPath)
			if err != nil {
				return fmt.Errorf("failed to open existing CSV file: %w", err)
			}

			reader := csv.NewReader(file)
			existingRecords, err = reader.ReadAll()
			file.Close()

			if err != nil {
				return fmt.Errorf("failed to read existing CSV: %w", err)
			}

			// Verify header is consistent
			if len(existingRecords) > 0 && len(existingRecords[0]) != len(headers) {
				return fmt.Errorf("existing CSV has different column structure")
			}
		}
	}

	// Create a new file (overwrite if exists)
	file, err := os.Create(csvResultPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if file didn't exist before or was empty
	if !fileExists {
		if err := writer.Write(headers); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
	} else if len(existingRecords) > 0 {
		// Write existing records
		if err := writer.WriteAll(existingRecords); err != nil {
			return fmt.Errorf("failed to write existing records: %w", err)
		}
	}

	// Write new row
	if err := writer.Write(csvData); err != nil {
		return fmt.Errorf("failed to write CSV data: %w", err)
	}

	return nil
}

func SaveResultReportLLMToTXT(serviceType Servicetype, result string) (string, error) {

	var filepath string

	// create dir
	if err := os.MkdirAll(OUTPUT_DIR_REPORT_LLM, 0755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}

	switch serviceType {
	case ServiceTypeVT:
		filepath = TXT_LLM_REPORT_VT_FILEPATH
	case ServiceTypeAbuseIPDB:
		filepath = TXT_LLM_REPORT_ABUSEIPDB_FILEPATH
	case ServiceTypeHybridAnalysis:
		filepath = TXT_LLM_REPORT_HYBRIDANALYSIS_FILEPATH
	case ServiceTypeIPQS:
		filepath = TXT_LLM_REPORT_IPQS_FILEPATH
	default:
		return "", fmt.Errorf("unsupported service type: %s", serviceType)
	}

	// save result to file txt and if file exists before, just overwrite it
	file, err := os.Create(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString(result)
	if err != nil {
		return "", fmt.Errorf("failed to write report content to file: %w", err)
	}

	return filepath, nil
}
