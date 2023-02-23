"""
routes.py
This module contains all the routes and view functions for the Flask app.
"""
import sys
import logging
import json
from flask_project import app
from flask_project.url_scanner import extract_urls, url_scan_info_check, url_domains_scan_info_check
from flask import render_template, request, jsonify
import validators
from .database_utils import (
    get_urls_domains
)
from .services import get_or_create_db_scan

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
log = logging.getLogger("flask_app")


@app.route("/")
def home_page():
    return render_template('base.html')

@app.route("/scan-text-urls", methods=["POST"])
def scan_text_urls():
    """
    This endpoint extracts all URLs from the text and performs a malicious URL scan on each URL using IPQS(). 
    The results of the scan are returned as a list of dictionaries.
    """
    text = request.json.get("text")
    if not text:
        return jsonify({"error": "Expecting 'text' in request body"}), 400
    urls = extract_urls(text)
    result = []
    for url in urls:
        result.append(get_or_create_db_scan(url))
    return result
    

@app.get('/search')
def domains_urls_query():
    """
    Perform a search for domains and urls associated with IP address that match a threat type.
    """
    threat_type = request.args.get('threat_type')
    return jsonify(get_urls_domains(threat_type))



@app.post("/send_url")
def send_url_to_IPQS():
    """
    Send a URL to the IPQS API for malicious content scanning.

    Returns:
        - json: Result of the scan in JSON format.
    """
    url_to_check = request.json.get("url")
    if not validators.url(url_to_check):
        return jsonify({"error": "No or wrong URL provided."}), 400
    
    return jsonify(get_or_create_db_scan(url_to_check)), 200


@app.route("/url_scan_info", methods = ["POST"])
def url_scan_info():
    """
    Funfction gets URLs names and return scan info from database

    Example of correct input json with URLs: 
        - {"1":"https://onet.pl", "2":"https://wp.pl"}
    :Return:
        - url_scan_result (json): URLs name with scan info parameters
    """
    url_input = request.get_json()
    url_list = list(url_input.values())
    url_scan_result = url_scan_info_check(url_list)
    return json.dumps(url_scan_result)


@app.route("/url_domains_scan_info", methods = ["POST"])
def url_domains_scan_info():
    """
    Funfction gets URL or domains names and return scan info from database

    Example of correct input json with URLs: 
        - {"1":"https://onet.pl", "2":"wp.pl"}
    :Return:
        - url_domains_scan_result (json): URLs name with scan info parameters
    """
    url_domains_input = request.get_json()
    url_domains_list = list(url_domains_input.values())
    url_domains_scan_result = url_domains_scan_info_check(url_domains_list)
    return json.dumps(url_domains_scan_result)
