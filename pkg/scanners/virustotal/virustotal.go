package virustotal

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
	BASE_DOMAIN_VIRUSTOTAL = "https://www.virustotal.com/api/v3"
)

var (
	VIRUS_TOTAL_API_KEY = os.Getenv("VIRUS_TOTAL_API_KEY")
)

func VirusTotalScan(api_key, target string, target_type utils.TargetType, save_to_csv bool) (bool, utils.ScanResultVT, string) {

	if api_key == "" {
		return false, utils.ScanResultVT{}, "API key for VirusTotal is not set. Please set the VIRUS_TOTAL_API_KEY environment variable."
	}

	virusTotalResp := new(utils.ScanResultVT)

	url := ""

	if target_type == utils.TargetTypeVTIP {
		url = BASE_DOMAIN_VIRUSTOTAL + "/ip_addresses/" + target
	} else if target_type == utils.TargetTypeVTDomain {
		url = BASE_DOMAIN_VIRUSTOTAL + "/domains/" + target
	} else if target_type == utils.TargetTypeVTHash {
		url = BASE_DOMAIN_VIRUSTOTAL + "/files/" + target
	} else {
		return false, *virusTotalResp, "Invalid target type provided. Please use one of the following: ip, domain, or hash."
	}

	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, *virusTotalResp, "Failed to create HTTP request: " + err.Error()
	}

	req.Header.Set("x-apikey", api_key)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, *virusTotalResp, "Failed to make HTTP request: " + err.Error()
	}

	defer func() {
		if resp.StatusCode != http.StatusOK {
			io.ReadAll(resp.Body) // Read the body to avoid resource leak
		}
		resp.Body.Close()
	}()

	scanResult, err := utils.ParseVirusTotalResponse(resp.Body)
	if err != nil {
		return false, *virusTotalResp, "Failed to parse response from VirusTotal: " + err.Error()
	}

	if save_to_csv {
		// save to csv
		if err := utils.SaveResultToCSV(target_type, target, scanResult, utils.ServiceTypeVT); err != nil {
			return false, *virusTotalResp, "Failed to save result to CSV: " + err.Error()
		} else {
			log.Printf("Scan result for target %s saved to CSV: %s file successfully.\n", target, utils.CSV_RESULT_VT_FILEPATH)
		}
	} else {
		log.Printf("Scan result for target %s not saved to CSV as save_to_csv is set to false.\n", target)
	}

	return true, *virusTotalResp, "Scan completed successfully."
}

func ProcessTargetListVT(targets []string, apiKey string) {

	existingTarget := utils.LoadExistingTargetScanned(utils.ServiceTypeVT)

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
		if target_type == "" {
			log.Printf("[%d/%d] Invalid target type for %s. Please use one of the following: ip, domain, or hash.", i+1, len(targets), target)
			continue
		}

		log.Printf("[%d/%d] Scanning Target: %s | Type: %s", i+1, len(targets), target, target_type)

		// if api key is not provided, try to use the environment variable
		if apiKey == "" {
			apiKey = VIRUS_TOTAL_API_KEY
		}

		// process scan here
		if ok, _, msg := VirusTotalScan(
			apiKey,
			target,
			utils.TargetType(target_type),
			true,
		); !ok {
			log.Printf("[%d/%d] Error scanning target %s: %s. Continue next target...", i+1, len(targets), target, msg)
		} else {

			// append target to result
			result = append(result, target)

			// human pause
			humanPause := rand.Float64()*(47-18) + 18
			log.Printf("Pausing for %.2f seconds to simulate human behavior...\n", humanPause)
			time.Sleep(time.Duration(humanPause) * time.Second)

		}

	}
}
