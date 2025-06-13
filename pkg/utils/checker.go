package utils

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

type TargetType string

const (
	TargetTypeVTIP     TargetType = "ip"
	TargetTypeVTDomain TargetType = "domain"
	TargetTypeVTHash   TargetType = "hash"
)

func IsIPAddress(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}

	// check if ipv4
	return strings.Count(s, ".") == 3
}

func IsDomainName(s string) bool {
	domainPattern := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainPattern.MatchString(s)
}

func IsHash(s string) bool {
	// MD5: 32 hex characters
	md5Pattern := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	if md5Pattern.MatchString(s) {
		return true
	}

	// SHA1: 40 hex characters
	sha1Pattern := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	if sha1Pattern.MatchString(s) {
		return true
	}

	// SHA256: 64 hex characters
	sha256Pattern := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	return sha256Pattern.MatchString(s)
}

func CheckTypeTarget(s string) string {
	if IsIPAddress(s) {
		return string(TargetTypeVTIP)
	} else if IsDomainName(s) {
		return string(TargetTypeVTDomain)
	} else if IsHash(s) {
		return string(TargetTypeVTHash)
	}
	return ""
}

func TargetExistInResultCSV(target string) bool {

	resultFile := filepath.Join(OUTPUT_DIR, CSV_FILENAME_VT)

	csvResult, err := NewCSVHelper(resultFile)
	if err != nil {
		log.Printf("Warning: %v\n", err)
		return false
	}

	return csvResult.TargetExists(target)
}

func CheckIfAllTargetSuccessfullyScanned(targets []string, serviceType Servicetype) bool {

	var messageService string

	if serviceType == ServiceTypeVT {
		messageService = "[VirusTotal only support for for IP, Domain, and Hash (SHA1, SHA256, MD5)]"
	} else if serviceType == ServiceTypeAbuseIPDB {
		messageService = "[AbuseIPDB only support for IP]"
	} else if serviceType == ServiceTypeHybridAnalysis {
		messageService = "[Hybrid Analysis only support for Hash (SHA1, SHA256, MD5)]"
	} else if serviceType == ServiceTypeIPQS {
		messageService = "[IPQualityScore only support for IP]"
	} else {
		log.Printf("Warning: Unsupported service type %s\n", serviceType)
		return false
	}

	existingTarget := LoadExistingTargetScannedAsMap(serviceType)

	fmt.Println("")

	allScanned := true
	for _, target := range targets {
		if _, exists := existingTarget[target]; !exists {
			log.Printf("Target %s has not been scanned yet (error happen, check target list again %s).\n", target, messageService)
			allScanned = false
		}
	}

	return allScanned
}
