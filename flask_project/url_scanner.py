"""
Url scanner module to work with urls/domains/ips.
"""
import json
import urllib
import socket
from urllib.parse import urlparse

import requests
import re

from .config import Config, RegularExpression
from .database_utils import get_url_scan_info, get_domain_scan_info


class IPQS:
    """
    IP Quality Score class used to send request to IPQualityScore API and get results about url.
    """

    key = Config.IPQS_SECRET_KEY  # API SECRET KEY

    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        """
        Scan a url for malicious content with IPQS API.

        Args:
            - url(str): Url to scan
            - vars(dict, optional): Additional parameters passed to API request.
                                    By default it's empty.
        """
        url = Config.IPQS_URL % (
            self.key,
            urllib.parse.quote_plus(url),
        )
        scan_result = requests.get(url, timeout=30, params=vars)
        return json.loads(scan_result.text)


def get_domain(url: str) -> str:
    """
    Input url, output domain of url.
    """
    parsed_url = urlparse(url)
    return parsed_url.netloc


def get_ip(domain: str) -> str:
    """
    Input domain, output ip of domain.
    """

    ip_address = socket.gethostbyname(domain)
    return ip_address


def url_validation(url):
    """
    Function check if given url name has correct URL structure

    :Parameters:
        - url (string): String with URL to check
    :Return:
        - True/False
    """
    validation = urlparse(url)
    return bool(validation.scheme and validation.netloc and validation.scheme in ['http', 'https'])


def domain_validation(domain):
    """
    Function check if given domain name has correct structure

    :Parameters:
        - domain (string): String with domain name to check
    :Return:
        - True/False
    """
    regex = RegularExpression.REGEX_DOMAIN
    return True if regex.match(domain) else False


def url_scan_info_check(url_list):
    """
    Function return scan info for given URLs names

    :Parameters:
        - url_list (list): List with URLs
    :Return:
        - scan_info (list): List with scan info for each given URLs names
    """
    scan_info = []
    for url in url_list:
        if url_validation(url):
            scan_info.append( get_url_scan_info(url))
        else:
            scan_info.append([url,"Wrong input - given string is not URL address"])
    return scan_info


def url_domains_scan_info_check(url_domains_list):
    """
    Function return scan info for given URL or domains names

    :Parameters:
        - url_domains_list (list): List with URL or domains names
    :Return:
        - scan_info (list): List with scan info for each given URL or domains names
    """
    scan_info = []
    for url in url_domains_list:
        if url_validation(url):
            scan_info.append( get_url_scan_info(url))
        elif domain_validation(url):
            scan_info.append(get_domain_scan_info(url))
        else:
            scan_info.append([url,"Wrong input - given string is not URL or domain address"])
    return scan_info
