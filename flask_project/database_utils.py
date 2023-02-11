"""
database_utils.py

This module stands for database management functions.
Adding new records, retrieving all records etc.
"""
from datetime import datetime
from .models import db, URL, IP_address, Domains


def get_url_scan_info(url_to_check):
    """
    Function check scan info in database for given URL name

    :Parameters:
        - url_to_check (string): URL name to check in database
    :Return:
        - scan_info (list): Scan info from database about given URL name
    """
    url_result = (db.session.query(URL.url, IP_address.category, 
                                    IP_address.server, IP_address.category, 
                                    IP_address.unsafe, IP_address.risk_score,
                                    IP_address.suspicious, IP_address.malware, 
                                    IP_address.phising, IP_address.spamming, 
                                    IP_address.parking, IP_address.dns_server,
                                    IP_address.dns_valid)
                .join(URL, IP_address.ip_id == URL.ip_id)
                .filter(URL.url == url_to_check)
                .all())
    if url_result == []:
        url_scan_info = [url_to_check,"URL is missing in database."]
    else:
        url_scan_info = [r._asdict() for r in url_result]
    return url_scan_info

def get_domain_scan_info (domain_to_check):
    """
    Function check scan info in database for given domain name

    :Parameters:
        - domain_to_check (string): Domain name to check in database
    :Return:
        - scan_info (list): Scan info from database about given URL name
    """

    domain_result = (db.session.query(Domains.domain_name, IP_address.category, 
                                        IP_address.server, IP_address.category, 
                                        IP_address.unsafe, IP_address.risk_score,
                                        IP_address.suspicious, IP_address.malware, 
                                        IP_address.phising, IP_address.spamming, 
                                        IP_address.parking, IP_address.dns_server,
                                        IP_address.dns_valid)
                .join(URL, IP_address.ip_id == URL.ip_id)
                .join(Domains, URL.domain_id == Domains.domain_id)
                .filter(Domains.domain_name == domain_to_check)
                .all())
    if domain_result == []:
        domain_scan_info = [domain_to_check,"Domain is missing in database."]
    else:
        domain_scan_info = [r._asdict() for r in domain_result]
    return domain_scan_info
