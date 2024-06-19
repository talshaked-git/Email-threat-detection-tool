# Email Threat Detection Tool

## Overview
The Email Threat Detection Tool is a Python-based application designed to analyze incoming emails for potential threats, such as malicious URLs, and flag suspicious emails. This tool leverages the IMAP protocol to fetch emails, extracts URLs from the email content, and uses the VirusTotal API to check for malicious indicators.

## Features
- Fetches emails from your inbox using IMAP.
- Extracts URLs from email content.
- Checks URLs against the VirusTotal API for malicious content.
- Displays threat analysis results on a web page.

## Setup Instructions

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)
- An email account with IMAP access enabled
- VirusTotal API key

### Installation

1. **Clone the repository**:
   ```sh
   git clone https://github.com/talshaked-git/email-threat-detection-tool.git
   cd email-threat-detection-tool
2. **Install the required dependencies**:
    pip install -r requirements.txt
3. **Configure environment variables**:
    - Create a .env file in the root of the project directory.
    - Add your email credentials and VirusTotal API key in the following format:
        EMAIL_ADDRESS="your_email@example.com"
      
        EMAIL_PASSWORD="your_password"
      
        VIRUSTOTAL_API_KEY="your_virustotal_api_key"

### Running the Application
1. **Run the application**
    python run.py
2. **Open your browser and navigate to**:
    http://127.0.0.1:5000/ (localhost:port5000)


## Usage
- The application will automatically fetch emails from your inbox, analyze them for potential threats, and display the results on the web page.
- For each email, it shows the sender, subject, and threat level based on the analysis of URLs found in the email content.

## Additional Information

### Email Account Setup
- Ensure your email account is configured to allow IMAP access.
- For Gmail users, you might need to enable "Less secure app access" or use an app-specific password.

### VirusTotal API Key
- Sign up for free for an API key on the [VirusTotal website](https://www.virustotal.com/gui/join-us).

## License
This project is licensed under the MIT License
