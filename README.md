StackGuard - Public Leakage Detection System

StackGuard is a Go-based scanner that detects sensitive tokens in public data sources. It scans a local file and public GitHub repositories, enriches the findings with basic geolocation, and sends immediate alerts via Slack and email.

This project fulfills the requirements of the "Public Leakage Detection System" assignment.

Features

Token Inventory: Scans against a JSON-based token inventory (inventory.json).

Dual-Source Scanning: Scans both local files (sample_leak.txt) and public GitHub repositories.

Geolocation Enrichment: Enriches GitHub leaks with the repository owner's location from their profile.

Multi-Channel Alerting: Sends alerts to both a Slack webhook and an email address (via Mailtrap for testing).

Containerized: Includes a Dockerfile and .dockerignore for a complete, reproducible, and secure build.

How It Works

Load Inventory: Reads the list of tokens to hunt for from inventory.json.

Load Config: Reads API keys and secrets from the .env file.

Local Scan: Scans the sample_leak.txt file for any matching tokens.

Public Scan: Uses the GitHub Code Search API to find any matching tokens in public repositories.

Alert: For every leak found, the handleAlerts function formats and sends a message to Slack and Mailtrap.

🚀 How to Run

Configuration (Required)

You must create a .env file in the root of this project. This file is critical.

Create the file: touch .env

Add your secrets. Do NOT use quotes around the values.

# .env file

# === GitHub ===
# Required for scanning GitHub.
# Get from: [https://github.com/settings/tokens/new](https://github.com/settings/tokens/new)
# Must have the [public_repo] scope.
GITHUB_TOKEN=ghp_...your_new_token_here...

# === Slack ===
# Your Slack Webhook URL.
SLACK_WEBHOOK_URL=[https://hooks.slack.com/services/](https://hooks.slack.com/services/)...

# === Mailtrap (for Email Testing) ===
# Use your SANDBOX credentials.
# Get from: Mailtrap -> Email Testing -> My Inbox
SMTP_HOST=sandbox.smtp.mailtrap.io
SMTP_PORT=2525
SMTP_USER=your-mailtrap-sandbox-username
SMTP_PASS=your-mailtrap-sandbox-password
SMTP_TO_EMAIL=your-test-email@example.com 


Option 1: Run with Docker (Recommended)

This is the easiest and most reliable way to run the project. It builds the scanner inside a container and securely injects your .env file.

1. Build the image:

docker build -t stackguard .


2. Run the container:

docker run --rm --env-file .env stackguard


Option 2: Run Locally (For Development)

This requires Go 1.24+ to be installed on your machine.

1. Install dependencies:
(If you haven't, initialize the Go module first)

# Run this once:
# go mod init stackguard
# go mod tidy


2. Run the scanner:
(The godotenv library will automatically load your .env file)

go run .


Demo & Example Alerts

Example Terminal Output

The scanner will log its progress, including any alerts it sends.

$ docker run --rm --env-file .env stackguard
Loaded environment variables from .env file
Successfully loaded 3 tokens.

--- Starting Local Scan ---
--- Handling 1 Alerts ---
------------------------------
Type:    GitHubToken
Source:  sample_leak.txt (line 6)
Snippet: config.api_key = "4q2w0e2r0t1y4u0i0op"
------------------------------
Successfully sent alert for GitHubToken to Slack.
Successfully sent alert for GitHubToken to Email (Mailtrap).

Starting GitHub Scan: 
Scanning GitHub for token: AWSKey...
Scanning GitHub for token: GitHubToken...
Scanning GitHub for token: AzureSecret...

--- Handling 3 Alerts ---
------------------------------
Type:    AWSKey
Source:  [https://github.com/some-user/test-repo/blob/main/config.ini](https://github.com/some-user/test-repo/blob/main/config.ini)
Snippet: Found in repo: some-user/test-repo
Geo:     San Francisco (GitHub Profile)
------------------------------
Successfully sent alert for AWSKey to Slack.
Successfully sent alert for AWSKey to Email (Mailtrap).
... (more alerts) ...

Scan complete.



