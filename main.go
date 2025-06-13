package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/manifoldco/promptui"
	"github.com/momokii/go-atscanner/pkg/llm"
	"github.com/momokii/go-atscanner/pkg/scanners/abuseipdb"
	"github.com/momokii/go-atscanner/pkg/scanners/hybridanalysis"
	"github.com/momokii/go-atscanner/pkg/scanners/ipqs"
	"github.com/momokii/go-atscanner/pkg/scanners/virustotal"
	"github.com/momokii/go-atscanner/pkg/utils"
	"github.com/momokii/go-llmbridge/pkg/openai"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	defer waitForEnter()

	var apiKeyLLM, apiKeyProvider string
	var serviceType utils.Servicetype
	usingLLM := false

	fmt.Printf("Starting Golang Automation Scanner...\n\n")

	// ================================= prompt user to select scan provider
	provider_scanner := []string{
		"VirusTotal",
		"AbuseIPDB",
		"Hybrid Analysis",
		"IPQualityScore",
	}
	prompt := promptui.Select{
		Label: "Select Scan Provider",
		Items: []string{
			provider_scanner[0] + " (IP, Hash, Domain)",
			provider_scanner[1] + " (Only IPs)",
			provider_scanner[2] + " Hybrid Analysis (Only Hashes)",
			provider_scanner[3] + " IPQualityScore (Only IPs)",
		},
		Size: 4,
	}

	idx, _, err := prompt.Run()

	if err != nil {
		fmt.Printf("Error selecting provider: %v\n", err)
		return
	}

	// ======================== prompt user to select if they want to use API Key for the selected provider
	prompt_api_key_provider := promptui.Select{
		Label: "Do you want to manual input API Key for the selected provider? (yes/no) or you set it in .env file (no need if you set it in .env file)",
		Items: []string{
			"yes",
			"no",
		},
		Size: 2,
	}

	idx_api_key, _, err := prompt_api_key_provider.Run()
	if err != nil {
		fmt.Printf("Error selecting API Key option: %v\n", err)
		return
	}

	// if say yes and need to manual input API Key, we will ask for API Key
	if idx_api_key == 0 {
		fmt.Printf("Input API Key for %s: ", provider_scanner[idx])
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		apiKeyProvider = scanner.Text()

		if apiKeyProvider == "" {
			log.Println("Error: Please provide a valid API Key.")
			return
		}

		switch idx {
		case 0:
			virustotal.VIRUS_TOTAL_API_KEY = apiKeyProvider
		case 1:
			abuseipdb.ABUSE_IP_DB_API_KEY = apiKeyProvider
		case 2:
			hybridanalysis.HYBRID_ANALYSIS_API_KEY = apiKeyProvider
		case 3:
			ipqs.IPQS_API_KEY = apiKeyProvider
		default:
			log.Println("Error: Invalid provider selected.")
			return
		}

		log.Printf("You using MANUAL INPUT API Key for %s.\n\n", provider_scanner[idx])
	} else {
		log.Printf("You using API Key from .env file for %s.\n\n", provider_scanner[idx])
	}

	// binding service type
	switch idx {
	case 0:
		serviceType = utils.ServiceTypeVT
	case 1:
		serviceType = utils.ServiceTypeAbuseIPDB
	case 2:
		serviceType = utils.ServiceTypeHybridAnalysis
	case 3:
		serviceType = utils.ServiceTypeIPQS
	}

	// =================================  prompt if user want to use LLM for report summary
	prompt_ai := promptui.Select{
		Label: "Do you want to use LLM for report summary? you need to provide API Key for this and using OpenAI API KEY (yes/no)",
		Items: []string{
			"yes",
			"no",
		},
		Size: 2,
	}

	idx_ai, _, err := prompt_ai.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// so if idx_ai == 0 (yes), we will ask for API Key
	if idx_ai == 0 {
		fmt.Printf("Input OpenAI API Key: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		apiKeyLLM = scanner.Text()
	}

	if idx_ai == 0 && apiKeyLLM == "" {
		log.Println("Error: Please provide a valid OpenAI API Key.")
		return
	}

	usingLLM = idx_ai == 0

	// =================================
	// MAIN SCANNER RUNNING
	//=================================

	if idx == 0 {

		if virustotal.VIRUS_TOTAL_API_KEY == "" {
			log.Println("Error: Please provide a valid VirusTotal API Key.")
			return
		}

		targets_file := filepath.Join("targets", "targets.csv")

		targets := utils.LoadTargetsFromCSV(targets_file)

		if len(targets) == 0 {
			log.Printf("Error: No targets found in the CSV file at %s\n", targets_file)
			return
		}

		log.Printf("Starting Virus Total scan for %d targets...\n", len(targets))

		virustotal.ProcessTargetListVT(targets, apiKeyProvider)

		// after all scan is done, save the scanned targets to a file
		if ok := utils.CheckIfAllTargetSuccessfullyScanned(targets, utils.ServiceTypeVT); ok {
			log.Println("All targets successfully scanned.")
		} else {
			log.Println("Some targets were not scanned successfully. Please check the logs for details.")
		}

	} else if idx == 1 {

		if abuseipdb.ABUSE_IP_DB_API_KEY == "" {
			log.Println("Error: Please provide a valid AbuseIPDB API Key.")
			return
		}

		targets_file := filepath.Join("targets", "targets.csv")

		targets := utils.LoadTargetsFromCSV(targets_file)

		if len(targets) == 0 {
			log.Printf("Error: No targets found in the CSV file at %s\n", targets_file)
			return
		}

		log.Printf("Starting AbuseIPDB scan for %d targets...\n", len(targets))

		abuseipdb.ProcessTargetListAbuseIPDB(targets, apiKeyProvider)

		// after all scan is done, save the scanned targets to a file
		if ok := utils.CheckIfAllTargetSuccessfullyScanned(targets, utils.ServiceTypeAbuseIPDB); ok {
			log.Println("All targets successfully scanned.")
		} else {
			log.Println("Some targets were not scanned successfully. Please check the logs for details.")
		}

	} else if idx == 2 {

		if hybridanalysis.HYBRID_ANALYSIS_API_KEY == "" {
			log.Println("Error: Please provide a valid Hybrid Analysis API Key.")
			return
		}

		targets_file := filepath.Join("targets", "targets.csv")
		targets := utils.LoadTargetsFromCSV(targets_file)

		if len(targets) == 0 {
			log.Printf("Error: No targets found in the CSV file at %s\n", targets_file)
			return
		}

		log.Printf("Starting Hybrid Analysis scan for %d targets...\n", len(targets))

		hybridanalysis.ProcessTargetListHybridAnalysis(targets, apiKeyProvider)

		if ok := utils.CheckIfAllTargetSuccessfullyScanned(targets, utils.ServiceTypeHybridAnalysis); ok {
			log.Println("All targets successfully scanned.")
		} else {
			log.Println("Some targets were not scanned successfully. Please check the logs for details.")
		}

	} else if idx == 3 {

		if ipqs.IPQS_API_KEY == "" {
			log.Println("Error: Please provide a valid IPQualityScore API Key.")
			return
		}

		targets_file := filepath.Join("targets", "targets.csv")
		targets := utils.LoadTargetsFromCSV(targets_file)

		if len(targets) == 0 {
			log.Printf("Error: No targets found in the CSV file at %s\n", targets_file)
			return
		}

		if len(targets) > 35 {
			log.Printf("Warning: Free Tier IPQualityScore API Key has a limit of 35 requests per day. Processing more than 35 targets may result in errors.")
		}

		fmt.Println("")
		log.Printf("Starting IPQualityScore scan for %d targets...\n", len(targets))

		ipqs.ProcessTargetListIPQS(targets, apiKeyProvider)

		if ok := utils.CheckIfAllTargetSuccessfullyScanned(targets, utils.ServiceTypeIPQS); ok {
			log.Println("All targets successfully scanned.")
		} else {
			fmt.Println("")
			log.Println("Some targets were not scanned successfully. Please check the logs for details.")
		}

	}

	// after main run, so check if user need to summary the result using llm
	if usingLLM {

		openaiClient, err := openai.New(
			apiKeyLLM,
			"",
			"",
			openai.WithModel("gpt-4.1-nano"),
		)
		if err != nil {
			log.Printf("Error creating OpenAI client: %v\n", err)
			return
		}

		fmt.Println("")
		log.Printf("Starting process LLM report summary...\n\n")

		log.Printf("Please wait, this may take a while...\n\n")

		// get summary result
		result, err := llm.CreateSummaryReport(
			serviceType,
			openaiClient,
		)
		if err != nil {
			log.Printf("Error creating summary report: %v\n", err)
			return
		}

		// save result to file to txt
		if filepath, err := utils.SaveResultReportLLMToTXT(serviceType, result); err != nil {
			log.Printf("Error saving summary report to file: %v\n", err)
			return
		} else {
			log.Printf("LLM Summary report successfully saved to: %s\n", filepath)
		}

	}

}

func waitForEnter() {
	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
