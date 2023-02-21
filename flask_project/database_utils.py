"""
database_utils.py
This module stands for database management functions.
Adding new records, retrieving all records etc.
"""
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from .models import db, URL, IP_address, Domains
from .config import Config


def create_ip_record(ipqs_data: dict):
    """
    Create an IP address record in the database.
    Args:
        - ipqs_data (dict): A dictionary containing data about ip address,
        from IP Quality Score Service.
    """
    current_datetime = datetime.now()
    ip_address_obj = IP_address(
        ip_address=ipqs_data["ip_address"],
        record_created_at=current_datetime,
        record_updated_at=current_datetime,
        server=ipqs_data["server"],
        category=ipqs_data["category"],
        unsafe=ipqs_data["unsafe"],
        risk_score=ipqs_data["risk_score"],
        suspicious=ipqs_data["suspicious"],
        malware=ipqs_data["malware"],
        phising=ipqs_data["phishing"],
        spamming=ipqs_data["spamming"],
        parking=ipqs_data["parking"],
        dns_server=False,  # TODO
        dns_valid=ipqs_data["dns_valid"],
    )
    db.session.add(ip_address_obj)
    db.session.commit()
    return ip_address_obj


def update_ip_record(ip_record, ipqs_data: dict):
    """
    Update IP record data based on ipqs response.
    """
    ip_record.ip_address = ipqs_data["ip_address"]
    ip_record.record_updated_at = datetime.now()
    ip_record.server = ipqs_data["server"]
    ip_record.category = ipqs_data["category"]
    ip_record.unsafe = ipqs_data["unsafe"]
    ip_record.risk_score = ipqs_data["risk_score"]
    ip_record.suspicious = ipqs_data["suspicious"]
    ip_record.malware = ipqs_data["malware"]
    ip_record.phising = ipqs_data["phishing"]
    ip_record.spamming = ipqs_data["spamming"]
    ip_record.parking = ipqs_data["parking"]
    ip_record.dns_valid = ipqs_data["dns_valid"]
    db.session.commit()


def create_domain_record(domain_name: str):
    """
    Create an domain record in the database.
    Args:
        - ipqs_data (dict): A dictionary containing data about ip address,
        from IP Quality Score Service.
    """
    current_datetime = datetime.now()
    domain_obj = Domains(
        domain_name=domain_name,
        record_created_at=current_datetime,
        record_updated_at=current_datetime,
    )
    db.session.add(domain_obj)
    db.session.commit()
    return domain_obj


def update_domain_record(domain_record):
    """
    Update field updated_at at domain records
    Args:
        - domain_record ()
    """
    domain_record.record_updated_at = datetime.now()
    db.session.commit()


def calculate_safety_status(ip_address_obj):
    """
    Calculate safety status
    Args:
        - ip_address_obj
    if risk score < 75 returns Low risk
    if risk score < 85 returns Suspicious
    if risk score < 100 returns High risk
    if risk score == 100 and Malware is true or Phishing is True returns Confirmed - Malware/Phising
    """
    score = int(ip_address_obj.risk_score)
    malware = ip_address_obj.malware
    phising = ip_address_obj.phising
    if score < 75:
        return "Low risk"
    elif score >= 75 and score < 85:
        return "Suspicious"
    elif score >= 85 and score < 100:
        return "High risk"
    elif score == 100 and malware or phising:
        return "Confirmed - Malware/Phising"


def create_url_record(url: str, domain_obj, ip_address_obj):
    """
    Create an url record in the database.
    Args:
        - url (str): Just url.
        - domain_obj (): Related to URL domain record from DB.
        - ip_addres_obj (): Related to URL IP address record from DB.
    """
    current_datetime = datetime.now()
    url_obj = URL(
        domain_id=domain_obj.domain_id,
        ip_id=ip_address_obj.ip_id,
        url=url,
        record_created_at=current_datetime,
        last_scan=current_datetime,
        added_by=1,  # TODO
        search_counter=1,
        safety_status=calculate_safety_status(ip_address_obj),
    )
    db.session.add(url_obj)
    db.session.commit()
    return url_obj


def update_url_record(url_record, ip_addres_obj):
    """
    Update an url record in database.
    Args:
        - url_record (): Url record
        - ip_addres_obj (): IP record
    """
    url_record.last_scan = datetime.now()
    url_record.search_counter = url_record.search_counter + 1
    url_record.safety_status = calculate_safety_status(ip_addres_obj)
    db.session.commit()


def check_last_scan(url_record):
    """
    Check if last scan was done at least 24h
    Args:
        - url_record (): url record obj
    """
    last_scan = url_record.last_scan
    current_time = datetime.now()
    time_since_last_scan = current_time - last_scan
    return time_since_last_scan > timedelta(hours=Config.HOURS)


def check_if_record_exists(model, field, value):
    """
    Check if record exists
    Args:
        - model () - IP/Domain/URL
        - field () - model Field
        - value () - model field value
    """
    record = model.query.filter(field == value).first()
    return record


def gather_url_informations(url_record):
    """
    Get data about url_record
    Args:
        - url_record () - url record obj
    Returns:
        - json ()
    """
    domain_obj = Domains.query.filter(Domains.domain_id == url_record.domain_id).first()
    ip_obj = IP_address.query.filter(IP_address.ip_id == url_record.ip_id).first()
    data = {
        "domain": domain_obj.domain_name,
        "ip": ip_obj.ip_address,
        "url": url_record.url,
        "safety_status": url_record.safety_status,
    }
    return data


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
    if url_result:
        url_scan_info = [r._asdict() for r in url_result]
    else:
        url_scan_info = [url_to_check,"URL is missing in database."]
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
    if domain_result:
        domain_scan_info = [r._asdict() for r in domain_result]
    else:
        domain_scan_info = [domain_to_check,"Domain is missing in database."]
    return domain_scan_info

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
