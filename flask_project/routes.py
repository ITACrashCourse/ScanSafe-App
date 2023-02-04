"""
routes.py
This module contains all the routes and view functions for the Flask app.
"""
from flask import render_template
from flask import jsonify
from flask import request

from flask_project import app

from .url_scanner import IPQS, get_domain, get_ip
from .database_utils import add_new_records


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
    # ip_address = get_ip(url_to_check) #TODO - fix the ip_address
    domain = get_domain(url_to_check)
    # TODO: CHECK IF DOMAIN/URL/IP ALREADY EXISTS
    # Here put function which will check if domain/url/ip are actually in our database.
    # If last scan of that record is less than for example 24h, provide results from database.
    # In other ways, send request to IPQS service.
    ipqs_response = IPQS().malicious_url_scanner_api(url_to_check)
    add_new_records(ipqs_response, url_to_check)
    print(ipqs_response)
    return jsonify(ipqs_response)
