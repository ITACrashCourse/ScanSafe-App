"""
routes.py
This module contains all the routes and view functions for the Flask app.
"""
import sys
import logging
import json
import hashlib
from flask_session import Session
from flask_project import app
from functools import wraps

from flask_project.url_scanner import IPQS, get_domain, extract_urls
from flask import render_template, request, jsonify, session, redirect, url_for
import validators

from .url_scanner import (IPQS, get_domain, get_ip, 
                          url_scan_info_check, url_domains_scan_info_check)
from .models import IP_address, URL, Domains
from .login_users import register_user
from .database_utils import (
    create_ip_record,
    create_domain_record,
    create_url_record,
    check_if_record_exists,
    gather_url_informations,
    check_last_scan,
    update_domain_record,
    update_ip_record,
    update_url_record,
    get_urls_domains,
    check_credentials
)

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
log = logging.getLogger("flask_app")


@app.route("/", methods=['GET', 'POST'])
def home_page():
    return render_template('home.html')


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
        result.append(IPQS().malicious_url_scanner_api(url))
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
    domain = get_domain(url_to_check)
    log.info("url domain: %s", str(domain))
    ip_address = get_ip(domain)
    log.info("ip of url: %s", str(ip_address))

    ip_record = check_if_record_exists(IP_address, IP_address.ip_address, ip_address)
    log.info("ip record: %s", str(ip_record))
    domain_record = check_if_record_exists(Domains, Domains.domain_name, domain)
    log.info("domain record: %s", str(domain_record))
    url_record = check_if_record_exists(URL, URL.url, url_to_check)
    log.info("url record: %s", str(url_record))

    if not url_record:
        ipqs_response = IPQS().malicious_url_scanner_api(url_to_check)
        if not ip_record:
            ip_record = create_ip_record(ipqs_response)
        if not domain_record:
            domain_record = create_domain_record(domain)
        url_record = create_url_record(url_to_check, domain_record, ip_record)
    else:
        if check_last_scan(url_record):  # To test change check_last_scan(url_record) to just True
            ipqs_response = IPQS().malicious_url_scanner_api(url_to_check)
            if not ip_record:
                ip_record = create_ip_record(ipqs_response)
            else:
                update_ip_record(ip_record, ipqs_response)
            if not domain_record:
                domain_record = create_domain_record(domain)
            else:
                update_domain_record(domain_record)
            update_url_record(url_record, ip_record)

    return jsonify(gather_url_informations(url_record)), 200


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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        registration = register_user(username,password,email)
        if registration:
            return redirect(url_for('login'))
    return render_template('register.html')

def login_required(funct):
    @wraps(funct)
    def decorated_function(*args, **kwargs):
        if session.get('username'):
            return funct(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return decorated_function
        

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        log_user = check_credentials(username, password)
        if log_user:
            session['username'] = username
            return redirect(url_for('main'))
        else:
            return redirect(url_for('login'))
    return render_template('login.html')
    

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route("/main", methods=["GET", "POST"])
@login_required
def main():
    return render_template('main.html')