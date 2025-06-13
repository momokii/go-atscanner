package hybridanalysis

import (
	"bytes"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/momokii/go-atscanner/pkg/utils"
)

const (
	BASE_DOMAIN_HYBRIDANALYSIS = "https://www.hybrid-analysis.com/api/v2"
)

var (
	HYBRID_ANALYSIS_API_KEY             = os.Getenv("HYBRID_ANALYSIS_API_KEY")
	HYBRID_ANALYSIS_API_URL_SEARCH_HASH = BASE_DOMAIN_HYBRIDANALYSIS + "/search/hash"
)

type HybridAnalysisDataSearchHash struct {
	Hash string `json:"hash"`
}

func HybridAnalysisScan(apiKey, target string, save_to_csv bool) (bool, string) {

	if apiKey == "" {
		return false, "API key for Hybrid Analysis is not set. Please set the HYBRID_ANALYSIS_API_KEY environment variable."
	}

	if target == "" {
		return false, "Target is empty. Please provide a valid domain to scan."
	}

	targetType := utils.CheckTypeTarget(target)

	if targetType != string(utils.TargetTypeVTHash) {
		return false, "Invalid target type provided. Hybrid Analysis only supports hashes."
	}

	inputData := HybridAnalysisDataSearchHash{
		Hash: target,
	}

	// Create form data
	formData := "hash=" + inputData.Hash

	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, HYBRID_ANALYSIS_API_URL_SEARCH_HASH, bytes.NewBufferString(formData))
	if err != nil {
		return false, "Failed to create HTTP request: " + err.Error()
	}

	// Add necessary headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("api-key", apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "Failed to make HTTP request: " + err.Error()
	}
	defer func() {
		if resp.StatusCode != http.StatusOK {
			// Read the body to avoid resource leak
			io.ReadAll(resp.Body)
		}
		resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "Failed to read response body: " + err.Error()
	}

	// Create a new reader with the same bytes for further processing
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return false, "Failed to scan target: " + string(bodyBytes)
	}

	// Check if the response is an empty array
	scanResultHA := new(utils.ScanResultHA)
	if string(bodyBytes) != "[]" {
		scanResultHA, err = utils.ParseSingleHybridAnalysisResponse(resp.Body)
		if err != nil {
			return false, "Failed to parse response from Hybrid Analysis: " + err.Error()
		}
	} else {
		log.Println("Hybrid Analysis returned empty result information for hash:", target)
	}

	if save_to_csv {

		if err := utils.SaveResultToCSV(utils.TargetTypeVTHash, target, scanResultHA, utils.ServiceTypeHybridAnalysis); err != nil {
			return false, "Failed to save scan result to CSV: " + err.Error()
		} else {
			log.Printf("Scan result for target %s saved to CSV successfully.\n", target)
		}

	} else {
		log.Printf("Scan result for target %s not saved to CSV as save_to_csv is set to false.\n", target)
	}

	return true, ""
}

func ProcessTargetListHybridAnalysis(targets []string, apiKey string) {

	existingTarget := utils.LoadExistingTargetScanned(utils.ServiceTypeHybridAnalysis)

	result := []string{}
	for i, target := range targets {

		found := false
		for _, existingT := range existingTarget {
			if existingT == target {
				found = true
				log.Printf("[%d/%d] Target already exists in result: %s. Skipping scan.", i+1, len(targets), target)
				break
			}
		}

		if found {
			continue
		}

		for _, existingT := range result {
			if existingT == target {
				found = true
				log.Printf("[%d/%d] Target already scanned in result: %s. Skipping scan.", i+1, len(targets), target)
				break
			}
		}

		if found {
			continue
		}

		targetType := utils.CheckTypeTarget(target)
		if targetType != string(utils.TargetTypeVTHash) {
			log.Printf("[%d/%d] Invalid target type for %s. Hybrid Analysis only supports hashes.", i+1, len(targets), target)
			continue
		}

		log.Printf("[%d/%d] Starting scan for target: %s", i+1, len(targets), target)

		// if api key is not provided, try to use the environment variable
		if apiKey == "" {
			apiKey = HYBRID_ANALYSIS_API_KEY
		}

		if success, msg := HybridAnalysisScan(
			apiKey,
			target,
			true, // save to CSV
		); !success {
			log.Printf("[%d/%d] Error scanning target %s: %s. Continue next target...", i+1, len(targets), target, msg)
		} else {

			result = append(result, target)

			// human pause
			humanPause := rand.Float64()*(3-1) + 1
			log.Printf("Pausing for %.2f seconds to simulate human behavior...\n", humanPause)
			time.Sleep(time.Duration(humanPause) * time.Second)

		}

	}

}
