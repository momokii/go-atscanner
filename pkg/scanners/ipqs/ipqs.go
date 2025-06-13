package ipqs

import (
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"

	"github.com/momokii/go-atscanner/pkg/utils"
)

const (
	BASE_DOMAIN_IPQS = "https://www.ipqualityscore.com/api/json"
)

var (
	IPQS_API_KEY         = os.Getenv("IPQS_API_KEY")
	IPQS_API_IP_SCAN_URL = BASE_DOMAIN_IPQS + "/ip/"
)

func IPQSScan(apiKey, target string, save_to_csv bool) (bool, string) {

	if apiKey == "" {
		return false, "API key for IPQualityScore is not set. Please set the IPQS_API_KEY environment variable."
	}

	if target == "" {
		return false, "Target is empty. Please provide a valid IP address to scan."
	}

	targetType := utils.CheckTypeTarget(target)

	if targetType != string(utils.TargetTypeVTIP) {
		return false, "Invalid target type provided. IPQualityScore only supports IP addresses."
	}

	url := IPQS_API_IP_SCAN_URL + apiKey + "/" + target

	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, "Failed to create HTTP request: " + err.Error()
	}

	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, "Failed to make HTTP request: " + err.Error()
	}

	defer func() {
		if resp.StatusCode != http.StatusOK {
			io.ReadAll(resp.Body)
		}
		resp.Body.Close()
	}()

	scanResult, err := utils.ParseIPQSResponse(resp.Body)
	if err != nil {
		return false, "Failed to parse IPQualityScore response: " + err.Error()
	}

	if save_to_csv {

		if err := utils.SaveResultToCSV(utils.TargetTypeVTIP, target, scanResult, utils.ServiceTypeIPQS); err != nil {
			return false, "Failed to save result to CSV: " + err.Error()
		} else {
			log.Printf("Scan result for target %s saved to CSV: %s file successfully.\n", target, utils.CSV_RESULT_IPQS_FILEPATH)
		}
	} else {
		log.Printf("Scan result for target %s not saved to CSV as save_to_csv is set to false.\n", target)
	}

	return true, ""
}

func ProcessTargetListIPQS(targets []string, apiKey string) {

	existingTarget := utils.LoadExistingTargetScanned(utils.ServiceTypeIPQS)

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
				log.Printf("[%d/%d] Target already scanned: %s. Skipping", i+1, len(targets), target)
				break
			}
		}

		if found {
			continue
		}

		targetType := utils.CheckTypeTarget(target)
		if targetType != string(utils.TargetTypeVTIP) {
			log.Printf("[%d/%d] Invalid target type for IPQualityScore: %s. Skipping scan.", i+1, len(targets), target)
			continue
		}

		log.Printf("[%d/%d] Scanning target: %s\n", i+1, len(targets), target)

		// if api key is not provided, try to use the environment variable
		if apiKey == "" {
			apiKey = IPQS_API_KEY
		}

		if ok, msg := IPQSScan(
			apiKey,
			target,
			true,
		); !ok {
			log.Printf("[%d/%d] Error scanning target %s: %s. Continue next target...", i+1, len(targets), target, msg)
		} else {

			result = append(result, target)

			humanPause := rand.Float64()*(3-1) + 1 // Random pause between 1 and 3 seconds
			log.Printf("[%d/%d] Scan completed for target %s. Pausing for %.2f seconds before next scan...\n", i+1, len(targets), target, humanPause)

		}

	}

}
