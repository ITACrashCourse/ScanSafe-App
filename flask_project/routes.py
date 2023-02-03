"""
routes.py
This module contains all the routes and view functions for the Flask app.
"""
from flask import render_template
from flask import jsonify
from flask import request

from flask_project import app

from .url_scanner import IPQS




@app.route("/")
def home_page():
    return render_template("base.html")

@app.post("/send_url")
def send_url_to_IPQS():
    url_to_check = request.json['url']
    ipqs_response = IPQS().malicious_url_scanner_api(url_to_check)
    print(ipqs_response)
    return jsonify(ipqs_response)