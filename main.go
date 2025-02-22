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

type IntegrationConfig struct {
	CreatedAt    string       `json:"created_at"`
	UpdatedAt    string       `json:"updated_at"`
	Descriptions Descriptions `json:"descriptions"`
}

type Descriptions struct {
	AppName             string    `json:"app_name"`
	AppDescription      string    `json:"app_description"`
	AppLogo             string    `json:"app_logo"`
	AppURL              string    `json:"app_url"`
	BackgroundColor     string    `json:"background_color"`
	IsActive            bool      `json:"is_active"`
	IntegrationType     string    `json:"integration_type"`
	IntegrationCategory string    `json:"integration_category"`
	KeyFeatures         []string  `json:"key_features"`
	Author              string    `json:"author"`
	Settings            []Setting `json:"settings"`
}

type Setting struct {
	Label     string `json:"label"`
	Type      string `json:"type"`
	Required  bool   `json:"required"`
	Default   string `json:"default"`
	TargetURL string `json:"target_url"`
	TickURL   string `json:"tick_url"`
}

func integrationHandler(w http.ResponseWriter, r *http.Request) {
	config := IntegrationConfig{
		CreatedAt: "2025-02-23",
		UpdatedAt: "2025-02-23",
		Descriptions: Descriptions{
			AppName:             "Container Vulnerability Scanner",
			AppDescription:      "This integration scans container images for vulnerabilities and notifies the user if high severity vulnerabilities are found.",
			AppLogo:             "",
			AppURL:              "",
			BackgroundColor:     "",
			IsActive:            true,
			IntegrationType:     "output",
			IntegrationCategory: "security",
			KeyFeatures: []string{
				"Scans container images for vulnerabilities",
				"Notifies user if high severity vulnerabilities are found",

			},
			Author: "Victor Akaaha",
			Settings: []Setting{
				{
					Label:     "Telex Endpoint",
					Type:      "text",
					Required:  true,
					Default:   "",
					TargetURL: "",
					TickURL:   "",
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		http.HandleFunc("/integration", integrationHandler)
		log.Println("Server is listening on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	} else {
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
}
