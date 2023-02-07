"""
database_utils.py

This module stands for database management functions.
Adding new records, retrieving all records etc.
"""
from datetime import datetime
from .models import db, URL, IP_address, Domains


def create_ip_record(ipqs_data: dict):
    """
    Create an IP address record in the database.
    Args:
        - ipqs_data (dict): A dictionary containing data about ip address,
        from IP Quality Score Service.
    """
    ip_address_obj = IP_address(
        ip_address=ipqs_data["ip_address"],
        record_created_at=datetime.now(),
        record_updated_at=datetime.now(),
        server=ipqs_data["server"],
        category=ipqs_data["category"],
        unsafe=ipqs_data["unsafe"],
        risk_score=ipqs_data["risk_score"],
        suspicious=ipqs_data["suspicious"],
        malware=ipqs_data["malware"],
        phising=ipqs_data["phishing"],
        spamming=ipqs_data["spamming"],
        parking=ipqs_data["spamming"],
        dns_server=False,  # TODO
        dns_valid=ipqs_data["dns_valid"],
    )
    db.session.add(ip_address_obj)
    db.session.commit()
    return ip_address_obj


def create_domain_record(ipqs_data: dict):
    """
    Create an domain record in the database.
    Args:
        - ipqs_data (dict): A dictionary containing data about ip address,
        from IP Quality Score Service.
    """
    domain_obj = Domains(
        domain_name=ipqs_data["domain"],
        record_created_at=datetime.now(),
        record_updated_at=datetime.now(),
    )
    db.session.add(domain_obj)
    db.session.commit()
    return domain_obj


def create_url_record(url: str, domain_obj, ip_address_obj):
    """
    Create an url record in the database.
    Args:
        - url (str): Just url.
        - domain_obj (): Related to URL domain record from DB.
        - ip_addres_obj (): Related to URL IP address record from DB.
    """
    url_obj = URL(
        domain_id=domain_obj.domain_id,
        ip_id=ip_address_obj.ip_id,
        url=url,
        record_created_at=datetime.now(),
        last_scan=datetime.now(),
        added_by=1,  # TODO
        search_counter=1,
        safety_status="low",  # TODO
    )
    db.session.add(url_obj)
    db.session.commit()
    return url_obj