package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/manifoldco/promptui"
	"github.com/momokii/go-atscanner/pkg/scanners/abuseipdb"
	"github.com/momokii/go-atscanner/pkg/scanners/hybridanalysis"
	"github.com/momokii/go-atscanner/pkg/scanners/ipqs"
	"github.com/momokii/go-atscanner/pkg/scanners/virustotal"
	"github.com/momokii/go-atscanner/pkg/utils"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	defer waitForEnter()

	// apiKey := ""
	// target := "121.166.2.253"
	// target := "kelanach.xyz"
	// target := "1bc5a8f426e2d3105bb4eb516027bac2"
	// save_to_csv := true

	// target_type_str := utils.CheckTypeTarget(target)
	// if target_type_str == "" {
	// 	log.Fatalf("Invalid target type for %s. Please use one of the following: ip, domain, or hash.", target)
	// }

	// target_type := utils.TargetType(target_type_str)

	// if ok, data, msg := virustotal.VirusTotalScan(
	// 	apiKey,
	// 	target,
	// 	target_type,
	// 	save_to_csv,
	// ); !ok {
	// 	log.Fatalf("Error: %s", msg)
	// } else {
	// 	log.Println("Scan Result:", ok)
	// 	log.Println("Data:", data)
	// 	log.Println("Message:", msg)
	// }

	// virustotal.VIRUS_TOTAL_API_KEY = apiKey
	// full ver
	fmt.Printf("Starting Golang Automation Scanner...\n")

	prompt := promptui.Select{
		Label: "Select Scan Provider",
		Items: []string{
			"VirusTotal (IP, Hash, Domain)",
			"AbuseIPDB (Only IPs)",
			"Hybrid Analysis (Only Hashes)",
			"IPQualityScore (Only IPs)",
		},
		Size: 4,
	}

	idx, _, err := prompt.Run()

	if err != nil {
		fmt.Printf("Error selecting provider: %v\n", err)
		return
	}

	// fmt.Printf("Input %s API Key: ", provider)
	// var apiKey string
	// scanner := bufio.NewScanner(os.Stdin)
	// scanner.Scan()
	// apiKey = scanner.Text()

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

		virustotal.ProcessTargetListVT(targets)

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

		abuseipdb.ProcessTargetListAbuseIPDB(targets)

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

		hybridanalysis.ProcessTargetListHybridAnalysis(targets)

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

		log.Printf("Starting IPQualityScore scan for %d targets...\n", len(targets))

		ipqs.ProcessTargetListIPQS(targets)

		if ok := utils.CheckIfAllTargetSuccessfullyScanned(targets, utils.ServiceTypeIPQS); ok {
			log.Println("All targets successfully scanned.")
		} else {
			log.Println("Some targets were not scanned successfully. Please check the logs for details.")
		}

	}

}

func waitForEnter() {
	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}
