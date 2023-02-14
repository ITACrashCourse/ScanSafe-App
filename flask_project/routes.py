from flask_project import app
from flask import request
from flask import render_template
from flask import jsonify
from .database_utils import get_urls_domains

@app.route('/')
def home_page():
    return render_template('base.html')


@app.get('/search')
def domains_urls_query():
    """
    Perform a search for domains and urls associated with IP address that match a threat type.
    """
    threat_type = request.args.get('threat_type')
    return jsonify(get_urls_domains(threat_type))