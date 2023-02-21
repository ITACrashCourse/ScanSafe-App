import sys
import logging
from flask_project import app
from flask_project.url_scanner import IPQS, get_domain
from .url_scanner import IPQS, get_domain, get_ip
from .models import IP_address, URL, Domains
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
)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
log = logging.getLogger("flask_app")

def get_or_create_db_scan(url):
    domain = get_domain(url)
    log.info("url domain: %s", str(domain))
    ip_address = get_ip(domain)
    log.info("ip of url: %s", str(ip_address))

    ip_record = check_if_record_exists(IP_address, IP_address.ip_address, ip_address)
    log.info("ip record: %s", str(ip_record))
    domain_record = check_if_record_exists(Domains, Domains.domain_name, domain)
    log.info("domain record: %s", str(domain_record))
    url_record = check_if_record_exists(URL, URL.url, url)
    log.info("url record: %s", str(url_record))

    if not url_record:
        ipqs_response = IPQS().malicious_url_scanner_api(url)
        if not ip_record:
            ip_record = create_ip_record(ipqs_response)
        if not domain_record:
            domain_record = create_domain_record(domain)
        url_record = create_url_record(url, domain_record, ip_record)
    else:
        if check_last_scan(url_record):  # To test change check_last_scan(url_record) to just True
            ipqs_response = IPQS().malicious_url_scanner_api(url)
            if not ip_record:
                ip_record = create_ip_record(ipqs_response)
            else:
                update_ip_record(ip_record, ipqs_response)
            if not domain_record:
                domain_record = create_domain_record(domain)
            else:
                update_domain_record(domain_record)
            update_url_record(url_record, ip_record)
    return gather_url_informations(url_record)