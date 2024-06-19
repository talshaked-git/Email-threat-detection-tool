import imaplib
import email
import requests
from dotenv import load_dotenv
import os
import logging
import re

load_dotenv()

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

logging.basicConfig(level=logging.INFO)

def fetch_emails():
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        logging.info("Logged in to email server successfully.")
        folder = 'inbox'   #adjust the folder to read mails from per email provider, for example google inbox : 'inbox'
        mail.select(folder)

        result, data = mail.search(None, 'ALL')
        email_ids = data[0].split()
        logging.info(f"Fetched {len(email_ids)} emails.")
        return email_ids, mail
    except Exception as e:
        logging.error(f"Failed to fetch emails: {e}")
        return [], None

def parse_email(raw_email):
    try:
        parsed_email = email.message_from_bytes(raw_email)
        return {
            'from': parsed_email['From'],
            'subject': parsed_email['Subject'],
            'body': get_email_body(parsed_email)
        }
    except Exception as e:
        logging.error(f"Failed to parse email: {e}")
        return None

def get_email_body(parsed_email):
    email_body = None
    for part in parsed_email.walk():
        content_type = part.get_content_type()
        if content_type == 'text/html':
            email_body = part.get_payload(decode=True)
            break  # Found HTML content, break the loop
        elif content_type == 'text/plain':
            try:
                email_body = part.get_payload(decode=True).decode('utf-8')
            except UnicodeDecodeError as e:
                logging.warning(f"UnicodeDecodeError: {e}")
                email_body = part.get_payload(decode=True).decode('latin-1', errors='ignore')
            break  # Found plain text content, break the loop

    if not email_body:
        logging.warning("No readable content found in email.")
    return email_body

def extract_urls(email_body):
    extracted_links = []

    # Regex pattern to capture URLs that start with http, https, or www or without them completely (just domain dot something)
    url_pattern = re.compile(r'(?:(?:https?://)?(?:www\.)?[-\w.]+\.[a-zA-Z]{2,}(?:/[-\w/]*)?)')

    urls = re.findall(url_pattern, email_body)

    # Clean up URLs by removing any angle brackets around them and add https:// if they dont have it for api schema requirements
    for url in urls:
        if 'https://' not in url:
            url = 'https://'+url
        extracted_links.append(url)

    # print(extracted_links)
    return extracted_links



def check_url_with_virustotal(url):
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    payload = {"url" : url}
    burl = "https://www.virustotal.com/api/v3/urls"
    try:
        response = requests.post(burl, data=payload, headers=headers)  #step 1: Post to scan URL and covert to JSON
        response.raise_for_status()
        scan_data = response.json()
        # print(f"Scan data is: {scan_data}")
        
        analysis_id = scan_data['data']['id'] #step 2: Get analysis ID
        # print(f"Analysis id is: {analysis_id}")
        
        
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}' #step 3: Get analysis details
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        analysis_data = response.json()
        
        #step 4: Check results for malicious indicators
        attributes = analysis_data['data']['attributes']
        if 'stats' in attributes:
            malicious_count = attributes['stats'].get('malicious', 0)
            if malicious_count > 0:
                return True
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to check URL with VirusTotal: {e}")
        
    except Exception as ex:
        logging.error(f"An unexpected error occurred: {ex}")
    
    return False


def check_urls(urls):
    for url in urls:
        if check_url_with_virustotal(url):
            return f'Malicious URL detected: {url}'
    return 'No malicious URLs found'

def fetch_and_analyze_emails():
    email_ids, mail = fetch_emails()
    emails = []

    if not mail:
        logging.error("Failed to connect to email server.")
        return emails

    for email_id in email_ids:
        result, message_data = mail.fetch(email_id, '(RFC822)')
        raw_email = message_data[0][1]
        email_data = parse_email(raw_email)

        if email_data:
            urls = extract_urls(email_data['body'])
            threat_level = check_urls(urls)
            emails.append({
                'from': email_data['from'],
                'subject': email_data['subject'],
                'threat_level': threat_level
            })

    return emails
