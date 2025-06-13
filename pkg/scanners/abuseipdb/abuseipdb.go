package abuseipdb

import (
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/momokii/go-atscanner/pkg/utils"
)

const (
	BASE_DOMAIN_ABUSEIPDB = "https://api.abuseipdb.com/api/v2"
)

var (
	ABUSE_IP_DB_API_KEY = os.Getenv("ABUSEIPDB_API_KEY")
)

func AbuselIPDBScan(api_key, target string, save_to_csv bool) (bool, string) {

	if api_key == "" {
		return false, "API key for AbuseIPDB is not set. Please set the ABUSE_IP_DB_API_KEY environment variable."
	}

	if target == "" {
		return false, "Target is empty. Please provide a valid IP address to scan."
	}

	// cheeck target, AbuseIPDB only supports IP addresses
	targetType := utils.CheckTypeTarget(target)

	if targetType != string(utils.TargetTypeVTIP) {
		return false, "Invalid target type provided. AbuseIPDB only supports IP addresses."
	}

	url := BASE_DOMAIN_ABUSEIPDB + "/check" + "?ipAddress=" + target

	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, "Failed to create HTTP request: " + err.Error()
	}

	req.Header.Set("Key", api_key)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "Failed to make HTTP request: " + err.Error()
	}

	defer func() {
		if resp.StatusCode != http.StatusOK {
			io.ReadAll(resp.Body) // Read the body to avoid resource leak
		}
		resp.Body.Close()
	}()

	scanResult, err := utils.ParseAbuseIPDBResponse(resp.Body)
	if err != nil {
		return false, "Failed to parse response from AbuseIPDB: " + err.Error()
	}

	if save_to_csv {

		if err := utils.SaveResultToCSV(utils.TargetTypeVTIP, target, scanResult, utils.ServiceTypeAbuseIPDB); err != nil {
			return false, "Failed to save scan result to CSV: " + err.Error()
		} else {
			log.Printf("Scan result for target %s saved to CSV: %s file successfully.\n", target, utils.CSV_RESULT_ABUSEIPDB_FILEPATH)
		}
	} else {
		log.Printf("Scan result for target %s not saved to CSV as save_to_csv is set to false.\n", target)
	}

	return true, ""
}

func ProcessTargetListAbuseIPDB(targets []string, apiKey string) {

	existingTarget := utils.LoadExistingTargetScanned(utils.ServiceTypeAbuseIPDB)

	result := []string{}
	for i, target := range targets {
		// Check if target is in existingTarget array
		found := false
		for _, existingT := range existingTarget {
			if existingT == target {
				found = true
				log.Printf("[%d/%d] Target already exist in result: %s. Skipping scan.", i+1, len(targets), target)
				break
			}
		}

		if found {
			continue
		}

		// also check if target is already scanned in result before
		for _, existingT := range result {
			if existingT == target {
				found = true
				log.Printf("[%d/%d] Target already scanned: %s. Skipping", i+1, len(targets), target)
				break
			}
		}

		if found {
			continue
		}

		target_type := utils.CheckTypeTarget(target)
		if target_type != string(utils.TargetTypeVTIP) {
			log.Printf("[%d/%d] Invalid target type for %s. AbuseIPDB just support for IP target", i+1, len(targets), target)
			continue
		}

		log.Printf("[%d/%d] Scanning Target: %s | Type: %s", i+1, len(targets), target, target_type)

		// if api key is not provided, try to use the environment variable
		if apiKey == "" {
			apiKey = ABUSE_IP_DB_API_KEY
		}

		// process scan here
		if ok, msg := AbuselIPDBScan(
			apiKey,
			target,
			true,
		); !ok {
			log.Printf("[%d/%d] Error scanning target %s: %s. Continue next target...", i+1, len(targets), target, msg)
		} else {

			// append target to result
			result = append(result, target)

			// human pause
			humanPause := rand.Float64()*(3-1) + 1
			log.Printf("Pausing for %.2f seconds to simulate human behavior...\n", humanPause)
			time.Sleep(time.Duration(humanPause) * time.Second)

		}

	}
}
