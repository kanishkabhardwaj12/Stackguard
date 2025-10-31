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
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	whois "github.com/likexian/whois-go"
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

type GitHubSearchResponse struct {
	TotalCount int    `json:"total_count"` // count of matches
	Items      []Item `json:"items"`
}

// Item represents a single search result (a file)
type Item struct {
	HTMLURL    string     `json:"html_url"` // link to the file
	Repository Repository `json:"repository"`
	Path       string     `json:"path"`
}

type Repository struct {
	FullName string `json:"full_name"`
	Owner    Owner  `json:"owner"`
}

type Owner struct {
	Login    string `json:"login"`
	Location string `json:"location"`
}

type gitHubCommitResponse []struct {
	Commit struct {
		Author struct {
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`
}

type SlackMessage struct {
	Text string `json:"text"`
}

func getWhoisLocation(domain string) (string, string) {
	result, err := whois.Whois(domain)
	if err != nil {
		log.Printf("WHOIS lookup failed for %s: %v", domain, err)
		return "", ""
	}

	cityRegex := regexp.MustCompile(`(?i)Registrant City: (.*)`)
	countryRegex := regexp.MustCompile(`(?i)Registrant Country: (.*)`)

	cityMatch := cityRegex.FindStringSubmatch(result)
	countryMatch := countryRegex.FindStringSubmatch(result)

	var location string
	if len(cityMatch) > 1 {
		location = strings.TrimSpace(cityMatch[1])
	}
	if len(countryMatch) > 1 {
		country := strings.TrimSpace(countryMatch[1])
		if location != "" {
			location = location + ", " + country
		} else {
			location = country
		}
	}

	if location != "" {
		location = strings.ReplaceAll(location, "\r", "")
		return location, "WHOIS Lookup"
	}

	return "", ""
}

func getCommitInfo(item Item, client *http.Client, githubToken string) (string, string) {

	// A blocklist of generic email domains
	genericDomains := map[string]bool{
		"gmail.com":                true,
		"hotmail.com":              true,
		"outlook.com":              true,
		"yahoo.com":                true,
		"aol.com":                  true,
		"icloud.com":               true,
		"protonmail.com":           true,
		"users.noreply.github.com": true,
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/commits?path=%s&per_page=1",
		item.Repository.FullName,
		item.Path,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating commit request: %v", err)
		return "", ""
	}
	req.Header.Add("Authorization", "Bearer "+githubToken)
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making commit request: %v", err)
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error: Commit API returned status: %s", resp.Status)
		return "", ""
	}

	var commitData gitHubCommitResponse
	err = json.NewDecoder(resp.Body).Decode(&commitData)
	if err != nil {
		log.Printf("Error parsing commit JSON: %v", err)
		return "", ""
	}

	if len(commitData) == 0 || commitData[0].Commit.Author.Email == "" {
		return "", ""
	}

	email := commitData[0].Commit.Author.Email
	parts := strings.Split(email, "@")

	if len(parts) != 2 {
		return "", ""
	}
	domain := parts[1]

	if genericDomains[domain] {
		return "", ""
	}

	location, method := getWhoisLocation(domain)
	if location != "" {
		return location, method
	}

	return domain, "Committer Email Domain"
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
		line := scanner.Text()
		for _, token := range tokens {
			if strings.Contains(line, token.Value) {
				leak := Leak{
					TokenType:  token.Type,
					SourceURL:  fmt.Sprintf("%s (line %d)", filePath, lineNumber),
					Snippet:    strings.TrimSpace(line),
					Confidence: 0.9,
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
		url := fmt.Sprintf("https://api.github.com/search/code?q=\"%s\"", token.Value)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Error creating request: %v", err)
			continue
		}
		req.Header.Add("Authorization", "Bearer "+githubToken)
		req.Header.Add("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error making request: %v", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Error: Github API returned status: %s", resp.Status)
			continue
		}

		var searchResult GitHubSearchResponse
		err = json.NewDecoder(resp.Body).Decode(&searchResult)
		resp.Body.Close()
		if err != nil {
			log.Printf("Error parsing JSON response: %v", err)
			continue
		}

		if searchResult.TotalCount > 0 {
			for _, item := range searchResult.Items {

				geoLocation, geoMethod := getCommitInfo(item, client, githubToken)

				if geoLocation == "" || geoLocation == item.Repository.Owner.Location {
					geoLocation = item.Repository.Owner.Location
					geoMethod = "GitHub Profile"
				}

				snippet := fmt.Sprintf("Found in repo: %s (File: %s)",
					item.Repository.FullName,
					item.Path,
				)

				leak := Leak{
					TokenType:   token.Type,
					SourceURL:   item.HTMLURL,
					Snippet:     snippet,
					Confidence:  0.9,
					GeoLocation: geoLocation,
					GeoMethod:   geoMethod,
				}
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

	from := "stackguard@mycompany.com"
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

	msg := []byte(
		"To: " + toEmail + "\r\n" +
			"From: " + from + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			body + "\r\n",
	)

	addr := host + ":" + port
	err := smtp.SendMail(addr, auth, from, []string{toEmail}, msg)
	if err != nil {
		log.Printf("Error sending email alert: %v", err)
		return
	}

	fmt.Printf("Successfully sent alert for %s to Email (Mailtrap).\n", leak.TokenType)
}

func handleAlerts(leaks []Leak, config AppConfig) {
	if len(leaks) == .0 {
		return
	}

	fmt.Printf("--- Handling %d Alerts ---\n", len(leaks))
	for _, leak := range leaks {
		fmt.Println("------------------------------")
		fmt.Printf("Type:    %s\n", leak.TokenType)
		fmt.Printf("Source:  %s\n", leak.SourceURL)
		fmt.Printf("Snippet: %s\n", leak.Snippet)
		if leak.GeoLocation != "" {
			fmt.Printf("Geo:     %s (%s)\n", leak.GeoLocation, leak.GeoMethod)
		}
		fmt.Println("------------------------------")

		if config.SlackWebhookURL != "" {
			sendSlackAlert(leak, config.SlackWebhookURL)
		}

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
	if err := godotenv.Load(); err == nil {
		fmt.Println("Loaded environment variables from .env file")
	}

	fileBytes, err := os.ReadFile("inventory.json")
	if err != nil {
		log.Fatalf("Failed to read inventory.json: %v", err)
	}

	var tokens []Token

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

	fmt.Println("\n--- Starting Local Scan ---")
	localLeaks := scanLocalFile("sample_leak.txt", tokens)
	if len(localLeaks) == 0 {
		fmt.Println("No leaks found in local scan. Good!")
	}

	handleAlerts(localLeaks, config)

	fmt.Println("\nStarting GitHub Scan: ")
	githubLeaks := scanGithub(tokens, config.GithubToken)
	if len(githubLeaks) == 0 {
		fmt.Println("No leaks found in GitHub scan. Good!")
	}

	handleAlerts(githubLeaks, config)

	fmt.Println("\nScan complete.")
}
