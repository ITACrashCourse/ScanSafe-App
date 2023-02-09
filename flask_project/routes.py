from flask_project import app
import sys
import logging
from flask import render_template
from flask import jsonify
from flask import request
from .models import db
import json
from flask import render_template

from .database_utils import url_scan_info_check

@app.route('/')
def home_page():
    return render_template('base.html')

@app.route("/url_scan_info", methods = ["POST"])
def url_scan_info():
    """
    Funfction gets URLs and return scan info from database
    
    Example of correct input json with URLs: 
        - {"1":"https://onet.pl", "2":"https://wp.pl"}
    :Return:
        - url_scan_result (json): URLs name with scan info parameters
    """
    url_input = request.get_json()
    url_list = list(url_input.values())
    url_scan_result = url_scan_info_check(url_list)
    return json.dumps(url_scan_result)
