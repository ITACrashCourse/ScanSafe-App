"""
database_utils.py

This module stands for database management functions.
Adding new records, retrieving all records etc.
"""
from datetime import datetime
from .models import db, URL, IP_address


def url_scan_info_check(url_list):
    """
    Function check scan info in database for get URLs

    :Parameters:
        - url_list (list): List with URLs
    :Return:
        - scan_info (list): List with scan ifnfo for each URL
    """
    scan_info = []
    for url in url_list:
        url_result = (db.session.query(URL.url, IP_address.category, IP_address.unsafe, IP_address.risk_score)
            .join(URL, IP_address.ip_id == URL.ip_id)
            .filter(URL.url == url)
            .all())
        scan_info.append([r._asdict() for r in url_result])
    return (scan_info)
