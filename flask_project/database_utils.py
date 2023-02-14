"""
database_utils.py
This module stands for database management functions.
Adding new records, retrieving all records etc.
"""
from .models import db, URL, IP_address, Domains


def get_urls_domains(threat_type: str):
    """
    Returns a dictionary with URLs and Domains associated with malware/spamming/phishing threat
    types.
    Args:
        threat_type (str): 'malware'/'phishing'/'spamming'
    Returns:
        dict: 
            - key1{urls} - threat type URLs
            - key2{domains} - threat type Domains
    """
    filters = {
        "malware": IP_address.malware == True,
        "spamming": IP_address.spamming == True,
        "phishing": IP_address.phising == True,
    }
    filter_condition = filters.get(threat_type)
    if filter_condition is None:
        return {"Error": "Wrong filter condition"}
    ip_records = IP_address.query.filter(filter_condition).all()
    urls = [
        url_rec.url
        for ip_rec in ip_records
        for url_rec in URL.query.filter_by(ip_id=ip_rec.ip_id)
    ]
    domain_ids = [
        url_rec.domain_id
        for ip_rec in ip_records
        for url_rec in URL.query.filter_by(ip_id=ip_rec.ip_id)
    ]
    domains = [
        domain_record.domain_name
        for domain_record in Domains.query.filter(Domains.domain_id.in_(domain_ids))
    ]

    return {"urls": urls, "domains": domains}
