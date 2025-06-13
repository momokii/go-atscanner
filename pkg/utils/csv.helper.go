package utils

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type CSVHelper struct {
	FilePath        string
	TargetColumnIdx int
	Header          []string
	Reader          *csv.Reader
	File            *os.File
}

func NewCSVHelper(filepath string) (*CSVHelper, error) {

	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return nil, err
	}

	// open csv file
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("error opening CSV file: %v", err)
	}

	reader := csv.NewReader(file)

	// read header
	header, err := reader.Read()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("error reading CSV header: %v", err)
	}

	targetColIdx := -1
	for i, col := range header {
		if col == "target" {
			targetColIdx = i
			break
		}
	}

	if targetColIdx == -1 {
		file.Close()
		return nil, fmt.Errorf("target column not found in CSV file")
	}

	return &CSVHelper{
		FilePath:        filepath,
		TargetColumnIdx: targetColIdx,
		Header:          header,
		Reader:          reader,
		File:            file,
	}, nil
}

func (h *CSVHelper) Close() {
	if h.File != nil {
		h.File.Close()
	}
}

func (h *CSVHelper) GetAllTargets() []string {
	var targets []string

	for {
		record, err := h.Reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Printf("Error reading record: %v\n", err)
			continue
		}

		if h.TargetColumnIdx < len(record) && record[h.TargetColumnIdx] != "" {
			targets = append(targets, record[h.TargetColumnIdx])
		}
	}

	return targets
}

func (h *CSVHelper) GetAllTargetAsMap() map[string]bool {
	targets := make(map[string]bool)

	for {
		record, err := h.Reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Printf("Error reading record: %v\n", err)
			continue
		}

		if h.TargetColumnIdx < len(record) && record[h.TargetColumnIdx] != "" {
			targets[strings.TrimSpace(record[h.TargetColumnIdx])] = true
		}
	}

	return targets
}

func (h *CSVHelper) TargetExists(target string) bool {
	for {
		record, err := h.Reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Printf("Error reading record: %v\n", err)
			continue
		}

		if h.TargetColumnIdx < len(record) && record[h.TargetColumnIdx] == target {
			return true
		}
	}

	return false
}

func LoadTargetsFromCSV(filepath string) []string {
	csvTarget, err := NewCSVHelper(filepath)
	if err != nil {
		fmt.Printf("Information: %v\n", err)
		return []string{}
	}
	defer csvTarget.Close()

	return csvTarget.GetAllTargets()
}

func LoadExistingTargetScanned(serviceType Servicetype) []string {
	var resultFile string

	if serviceType == ServiceTypeVT {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_VT)
	} else if serviceType == ServiceTypeAbuseIPDB {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_ABUSEIPDB)
	} else if serviceType == ServiceTypeHybridAnalysis {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_HYBRIDANALYSIS)
	} else if serviceType == ServiceTypeIPQS {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_IPQS)
	} else {
		fmt.Printf("Warning: Unsupported service type %s\n", serviceType)
		return []string{}
	}

	csvTarget, err := NewCSVHelper(resultFile)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		return []string{}
	}
	defer csvTarget.Close()

	return csvTarget.GetAllTargets()
}

func LoadExistingTargetScannedAsMap(serviceType Servicetype) map[string]bool {
	var resultFile string
	if serviceType == ServiceTypeVT {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_VT)
	} else if serviceType == ServiceTypeAbuseIPDB {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_ABUSEIPDB)
	} else if serviceType == ServiceTypeHybridAnalysis {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_HYBRIDANALYSIS)
	} else if serviceType == ServiceTypeIPQS {
		resultFile = filepath.Join(OUTPUT_DIR, CSV_FILENAME_IPQS)
	} else {
		fmt.Printf("Warning: Unsupported service type %s\n", serviceType)
		return map[string]bool{}
	}

	csvTarget, err := NewCSVHelper(resultFile)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		return map[string]bool{}
	}
	defer csvTarget.Close()

	return csvTarget.GetAllTargetAsMap()
}

func OpenCSVServiceResult(serviceType Servicetype) (result string, err error) {

	resultFiles := map[Servicetype]string{
		ServiceTypeVT:             CSV_RESULT_VT_FILEPATH,
		ServiceTypeAbuseIPDB:      CSV_RESULT_ABUSEIPDB_FILEPATH,
		ServiceTypeHybridAnalysis: CSV_RESULT_HYBRIDANALYSIS_FILEPATH,
		ServiceTypeIPQS:           CSV_RESULT_IPQS_FILEPATH,
	}

	filepath, exists := resultFiles[serviceType]
	if !exists {
		return "", fmt.Errorf("unsupported service type: %s", serviceType)
	}

	// process and open file
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return "", fmt.Errorf("result file does not exist: %s", filepath)
	}

	// read content
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("error opening result file: %v", err)
	}
	defer file.Close()

	// process csv
	reader := csv.NewReader(file)

	// read record
	records, err := reader.ReadAll()
	if err != nil {
		return "", fmt.Errorf("error reading CSV file: %v", err)
	}

	// so the data is null because max just the csv header column
	if len(records) < 2 {
		return "", fmt.Errorf("no data found in the CSV file: %s", filepath)
	}

	// format result
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s Scan Results\n\n", serviceType))

	headers := records[0]

	sb.WriteString("| ")
	for _, header := range headers {
		sb.WriteString(header)
		sb.WriteString(" | ")
	}
	sb.WriteString("\n|")

	// separator row
	for range headers {
		sb.WriteString(" --- |")
	}
	sb.WriteString("\n")

	// write data row, and ofc start with no 2 because no 1 is header csv
	for _, record := range records[1:] {
		if len(record) == 0 {
			continue // skip for empty row
		}

		sb.WriteString("| ")
		for i, value := range record {
			if i < len(headers) {
				sb.WriteString(value)
				sb.WriteString(" | ")
			}
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}
