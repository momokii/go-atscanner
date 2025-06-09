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
