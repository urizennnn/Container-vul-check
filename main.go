package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type Vulnerability struct {
	Severity string `json:"Severity"`
}

type Result struct {
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type TrivyScanResult struct {
	Results []Result `json:"Results"`
}

func scanImage(image string) (*TrivyScanResult, error) {
	cmd := exec.Command("trivy", "image", "--quiet", "--format", "json", image)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error scanning image %s: %v", image, err)
	}
	var scanResults TrivyScanResult
	if err := json.Unmarshal(output, &scanResults); err != nil {
		return nil, fmt.Errorf("error parsing JSON output: %v", err)
	}
	return &scanResults, nil
}

func evaluateVulnerabilities(scanResults *TrivyScanResult, severityThreshold string) []Vulnerability {
	thresholdLevels := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}
	thresholdValue, ok := thresholdLevels[strings.ToUpper(severityThreshold)]
	if !ok {
		thresholdValue = 3
	}
	var flagged []Vulnerability
	for _, result := range scanResults.Results {
		for _, vuln := range result.Vulnerabilities {
			sev := strings.ToUpper(vuln.Severity)
			if level, exists := thresholdLevels[sev]; exists && level >= thresholdValue {
				flagged = append(flagged, vuln)
			}
		}
	}
	return flagged
}

func notifyTelex(message, telexEndpoint string) bool {
	payload := map[string]string{"message": message}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON payload: %v", err)
		return false
	}
	resp, err := http.Post(telexEndpoint, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Error sending request to Telex: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to notify Telex integration. HTTP status: %d", resp.StatusCode)
		return false
	}
	return true
}

func main() {

	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <container_image> <telex_endpoint>")
		os.Exit(1)
	}
	containerImage := os.Args[1]
	telexEndpoint := os.Args[2]
	fmt.Printf("Scanning container image: %s\n", containerImage)
	scanResults, err := scanImage(containerImage)
	if err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
	flaggedVulns := evaluateVulnerabilities(scanResults, "HIGH")
	if len(flaggedVulns) > 0 {
		message := fmt.Sprintf("Vulnerability Scan Alert: %d high/critical vulnerability(s) found in %s. Please review immediately.", len(flaggedVulns), containerImage)
		fmt.Println(message)
		if notifyTelex(message, telexEndpoint) {
			fmt.Println("Telex notified successfully. Halting pipeline.")
			os.Exit(1)
		} else {
			fmt.Println("Telex notification failed. Halting pipeline.")
			os.Exit(1)
		}
	} else {
		fmt.Println("No high severity vulnerabilities detected. Proceeding with pipeline.")
		os.Exit(0)
	}
}
