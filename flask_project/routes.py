from flask import render_template, request
from flask_project import app
from flask_project.url_scanner import IPQS, get_domain, extract_urls

@app.route('/')
def home_page():
    return render_template('base.html')

# Scan text urls via IP Quality Score service.
@app.route("/scan-text-urls", methods=["POST"])
def scan_text_urls():
    body = request.json
    text = body["text"]
    urls = extract_urls(text)
    result = []
    for url in urls:
        domain = get_domain(url)
        result.append(IPQS().malicious_url_scanner_api(domain))
    return result