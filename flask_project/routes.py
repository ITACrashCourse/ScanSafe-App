"""
routes.py
This module contains all the routes and view functions for the Flask app.
"""
from flask import render_template
from flask import jsonify
from flask import request
import validators

from flask_project import app

from .url_scanner import IPQS, get_domain, get_ip
from .database_utils import create_ip_record, create_domain_record, create_url_record


@app.route("/")
def home_page():
    return render_template("base.html")


@app.post("/send_url")
def send_url_to_IPQS():
    """
    Send a URL to the IPQS API for malicious content scanning.

    Returns:
        - json: Result of the scan in JSON format.
    """
    url_to_check = request.json["url"]
    if not validators.url(url_to_check):
        return jsonify({'error': 'No or wrong URL provided.'}), 400
    
    domain = get_domain(url_to_check)
    print(domain)
    ip_address = get_ip(domain) #TODO - fix the ip_address
    print(ip_address)
    # TODO: CHECK IF DOMAIN/URL/IP ALREADY EXISTS
    # Here put function which will check if domain/url/ip are actually in our database.
    # If last scan of that record is less than for example 24h, provide results from database.
    # In other ways, send request to IPQS service.
    ipqs_response = IPQS().malicious_url_scanner_api(url_to_check)
    ip_record = create_ip_record(ipqs_response)
    domain_record = create_domain_record(ipqs_response)
    url_record = create_url_record(url_to_check, domain_record, ip_record)
    print(ipqs_response)
    return jsonify(ipqs_response), 200
