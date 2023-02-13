from flask import render_template, request
from flask_project import app
from flask_project.url_scanner import IPQS, get_domain, extract_urls

@app.route('/')
def home_page():
    return render_template('base.html')

@app.route("/scan-text-urls", methods=["POST"])
def scan_text_urls():
    """
    this endpoint extracts all URLs from the text and performs a malicious URL scan on each URL using IPQS(). 
    The results of the scan are returned as a list of dictionaries.
    """
    text = request.json["text"]
    urls = extract_urls(text)
    result = []
    for url in urls:
        result.append(IPQS().malicious_url_scanner_api(url))
    return result
    