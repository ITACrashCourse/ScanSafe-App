from flask_project import app
from flask_project.url_scanner import IPQS, get_domain
from flask import render_template, request

@app.route('/')
def home_page():
    return render_template('base.html')

# Scan URL via IP Quality Score service.
@app.route("/scan-url", methods=["POST"])
def scan_url():
    url = request.args.get('url')
    domain = get_domain(url)
    result = IPQS().malicious_url_scanner_api(domain)
    return result