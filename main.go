package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Token struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Owner string `json:"owner"`
}

type Leak struct {
	TokenType   string  `json:"tokenType"`
	SourceURL   string  `json:"sourceURL"`
	Snippet     string  `json:"snippet"`
	Confidence  float64 `json:"confidence"`
	GeoLocation string  `json:"geoLocation"`
	GeoMethod   string  `json:"geoMethod"`
}

// ### FIX 1 (A): GitHub Structs Corrected ###
// The 'Owner' struct is now correctly placed *inside* the 'Repository' struct.
// ---

type GitHubSearchResponse struct {
	TotalCount int    `json:"total_count"` // count of matches
	Items      []Item `json:"items"`
}

// Item represents a single search result (a file)
type Item struct {
	HTMLURL    string     `json:"html_url"` // link to the file
	Repository Repository `json:"repository"`
	// 'Owner' field removed from here
}

// Repository holds the repo details
type Repository struct {
	FullName string `json:"full_name"`
	Owner    Owner  `json:"owner"` // 'Owner' field added here
}

// Geolocation data
type Owner struct {
	Login    string `json:"login"`
	Location string `json:"location"` // user's profile location
}

// --- End of Fix 1 (A) ---

type SlackMessage struct {
	Text string `json:"text"`
}

func scanLocalFile(filePath string, tokens []Token) []Leak {
	var foundLeaks []Leak

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Warning: Could not open file %s: %v", filePath, err)
		return foundLeaks
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text() //get the current line as string
		for _, token := range tokens {
			if strings.Contains(line, token.Value) {
				leak := Leak{
					TokenType:  token.Type,
					SourceURL:  fmt.Sprintf("%s (line %d)", filePath, lineNumber),
					Snippet:    strings.TrimSpace(line),
					Confidence: 0.9, // cant say with 100% surity because this match could be a placeholder
				}
				foundLeaks = append(foundLeaks, leak)
			}
		}
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: Error scanning file %s: %v", filePath, err)
	}

	return foundLeaks
}

func scanGithub(tokens []Token, githubToken string) []Leak {
	var foundLeaks []Leak

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, token := range tokens {
		fmt.Printf("Scanning GitHub for token: %s...\n", token.Type)
		// send a request to search for each token
		url := fmt.Sprintf("https://api.github.com/search/code?q=\"%s\"", token.Value)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Error creating request: %v", err)
			continue
		}
		// add headers
		req.Header.Add("Authorization", "Bearer "+githubToken)
		req.Header.Add("Accept", "application/vnd.github.v3+json")

		// make request
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error making request: %v", err)
			continue
		}

		// check bad response
		if resp.StatusCode != http.StatusOK {
			log.Printf("Error: Github API returned status: %s", resp.Status)
			continue
		}

		// decode response
		var searchResult GitHubSearchResponse
		err = json.NewDecoder(resp.Body).Decode(&searchResult)
		resp.Body.Close()
		if err != nil {
			log.Printf("Error parsing JSON response: %v", err)
			continue
		}

		if searchResult.TotalCount > 0 {
			for _, item := range searchResult.Items {
				// ### FIX 1 (B): GeoLocation Path Corrected ###
				// Changed from 'item.Owner.Location' to 'item.Repository.Owner.Location'
				leak := Leak{
					TokenType:  token.Type,
					SourceURL:  item.HTMLURL,
					Snippet:    fmt.Sprintf("Found in repo: %s", item.Repository.FullName),
					Confidence: 0.9,
					// get the location from the user's profile
					GeoLocation: item.Repository.Owner.Location, // <-- Corrected path
					GeoMethod:   "GitHub Profile",
				}
				// --- End of Fix 1 (B) ---
				foundLeaks = append(foundLeaks, leak)
			}
		}
		time.Sleep(10 * time.Second)
	}

	return foundLeaks

}

func sendSlackAlert(leak Leak, webhookURL string) {
	messageText := fmt.Sprintf(
		":warning: Leak Detected :warning:\n\n"+
			"Token Type: %s\n"+
			"Source: %s\n"+
			"Snippet: `%s`\n"+
			"Geolocation: %s (%s)\n"+
			"Action: Please revoke this token immediately!",
		leak.TokenType, leak.SourceURL, leak.Snippet, leak.GeoLocation, leak.GeoMethod,
	)
	payload := SlackMessage{
		Text: messageText,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error creating Slack JSON payload: %v", err)
		return
	}
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Error sending Slack alert: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error: Slack API returned status: %s", resp.Status)
	} else {
		fmt.Printf("Successfully sent alert for %s to Slack.\n", leak.TokenType)
	}
}

func sendEmailAlert(leak Leak, host, port, user, pass, toEmail string) {
	auth := smtp.PlainAuth("", user, pass, host)

	from := "kanishka@mailsystem.com"
	subject := fmt.Sprintf("CRITICAL: Leak Detected (%s)", leak.TokenType)
	body := fmt.Sprintf(
		"A secret leak has been detected:\n\n"+
			"Token Type: %s\n"+
			"Source: %s\n"+
			"Snippet: %s\n"+
			"Geolocation: %s (%s)\n\n"+
			"ACTION REQUIRED: Please revoke this token immediately.",
		leak.TokenType, leak.SourceURL, leak.Snippet, leak.GeoLocation, leak.GeoMethod,
	)

	// The full message combines headers and body
	msg := []byte(
		"To: " + toEmail + "\r\n" +
			"From: " + from + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" + // Empty line separates headers from body
			body + "\r\n",
	)

	// Send the email
	addr := host + ":" + port
	err := smtp.SendMail(addr, auth, from, []string{toEmail}, msg)
	if err != nil {
		log.Printf("Error sending email alert: %v", err)
		return
	}

	fmt.Printf("Successfully sent alert for %s to Email (Mailtrap).\n", leak.TokenType)
}

func handleAlerts(leaks []Leak, config AppConfig) {
	if len(leaks) == 0 {
		return // No leaks, nothing to do
	}

	fmt.Printf("--- Handling %d Alerts ---\n", len(leaks))
	for _, leak := range leaks {
		// Print to console
		fmt.Println("------------------------------")
		fmt.Printf("Type:    %s\n", leak.TokenType)
		fmt.Printf("Source:  %s\n", leak.SourceURL)
		fmt.Printf("Snippet: %s\n", leak.Snippet)
		if leak.GeoLocation != "" {
			fmt.Printf("Geo:     %s (%s)\n", leak.GeoLocation, leak.GeoMethod)
		}
		fmt.Println("------------------------------")

		// Send to Slack
		if config.SlackWebhookURL != "" {
			sendSlackAlert(leak, config.SlackWebhookURL)
		}

		// Send to Email
		if config.SMTPHost != "" {
			sendEmailAlert(leak, config.SMTPHost, config.SMTPPort, config.SMTPUser, config.SMTPPass, config.SMTPToEmail)
		}
	}
}

type AppConfig struct {
	GithubToken     string
	SlackWebhookURL string
	SMTPHost        string
	SMTPPort        string
	SMTPUser        string
	SMTPPass        string
	SMTPToEmail     string
}

func main() {
	// 1. Load Inventory (This part was correct)
	fileBytes, err := os.ReadFile("inventory.json")
	if err != nil {
		log.Fatalf("Failed to read inventory.json: %v", err)
	}

	var tokens []Token // to store the list of tokens from inventory

	err = json.Unmarshal(fileBytes, &tokens)
	if err != nil {
		log.Fatalf("Failed to parse inventory.json: %v", err)
	}
	fmt.Printf("Successfully loaded %d tokens.\n", len(tokens))

	config := AppConfig{
		GithubToken:     os.Getenv("GITHUB_TOKEN"),
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		SMTPHost:        os.Getenv("SMTP_HOST"),
		SMTPPort:        os.Getenv("SMTP_PORT"),
		SMTPUser:        os.Getenv("SMTP_USER"),
		SMTPPass:        os.Getenv("SMTP_PASS"),
		SMTPToEmail:     os.Getenv("SMTP_TO_EMAIL"),
	}

	if config.GithubToken == "" {
		log.Fatalf("GITHUB_TOKEN environment variable is not set. Exiting.")
	}
	if config.SlackWebhookURL == "" {
		log.Println("Warning: SLACK_WEBHOOK_URL not set. Slack alerts are disabled.")
	}
	if config.SMTPHost == "" {
		log.Println("Warning: SMTP_HOST not set. Email alerts are disabled.")
	}

	// Run Local Scan
	fmt.Println("\n--- Starting Local Scan ---")
	localLeaks := scanLocalFile("sample_leak.txt", tokens)
	if len(localLeaks) == 0 {
		fmt.Println("No leaks found in local scan. Good!")
	}

	// Send local leaks to the alerting system
	handleAlerts(localLeaks, config)

	// Run GitHub Scan
	fmt.Println("\nStarting GitHub Scan: ")
	githubLeaks := scanGithub(tokens, config.GithubToken)
	if len(githubLeaks) == 0 {
		fmt.Println("No leaks found in GitHub scan. Good!")
	}

	// Send GitHub leaks to the alerting system
	handleAlerts(githubLeaks, config)

	fmt.Println("\nScan complete.")
}
