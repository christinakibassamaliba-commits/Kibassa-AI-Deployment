# Kibassa AI

**An AI-powered cybersecurity analysis platform built with Python and Streamlit.**

Kibassa AI is a personal cybersecurity project designed to help users identify potential security risks in suspicious emails, URLs, and attachment filenames.

## Features

- **Phishing Email Analysis:** Examines email content for suspicious language, links, and common phishing indicators.
- **URL Analysis:** Evaluates URLs for potential security warning signs.
- **Attachment Filename Analysis:** Checks filenames and extensions for potential risks. It does not scan actual file contents.
- **Risk Scoring:** Uses rule-based detection to calculate risk scores independently of AI-generated explanations.
- **AI-Assisted Explanations:** Uses Google's Gemini API to explain security findings.
- **PDF Reports:** Generates downloadable security reports.
- **Scan History:** Displays recent scan records temporarily within each user's Streamlit session.

## Technologies Used

- Python
- Streamlit
- Google Gemini API
- ReportLab

## Running Locally

1. Install Python.
2. Download or clone this repository.
3. Install the required packages:

   `pip install -r requirements.txt`

4. Create a `.streamlit/secrets.toml` file with your own Gemini API key:

   `GEMINI_API_KEY = "YOUR_API_KEY_HERE"`

5. Start the application:

   `streamlit run app.py`

## Important Notes

Kibassa AI is an educational and portfolio project. Its risk assessments are informational and should not replace professional security analysis.

The attachment analyzer evaluates filenames and extensions, not the contents of uploaded files.

Scan history is stored temporarily in Streamlit session state rather than in a persistent database. It is not designed for long-term record storage.

Never commit `.streamlit/secrets.toml` or API keys to a public repository.

## Project Status

Currently preparing for public deployment.