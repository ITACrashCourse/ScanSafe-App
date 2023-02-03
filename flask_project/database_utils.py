from datetime import datetime
from .models import db, URL, IP_address, Domains


def add_new_records(ipqs_data: dict, url:str):
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
        dns_server="unknown", # TODO
        dns_valid=ipqs_data["dns_valid"]
    )
    db.session.add(ip_address_obj)
    db.session.flush()

    domain_obj = Domains(
        domain_name=ipqs_data["domain"],
        record_created_at=datetime.now(),
        record_updated_at=datetime.now(),
    )
    db.session.add(domain_obj)
    db.session.flush()

    url_obj = URL(
        domain_id=domain_obj,
        ip_id=ip_address_obj,
        url=url,
        record_created_at = datetime.now(),
        last_scan = datetime.now(),
        added_by = 1, #TODO
        search_counter = 1,
        safety_status = "low" #TODO
    )
    db.session.add(url_obj)
    db.session.commit()
