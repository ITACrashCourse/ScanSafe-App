"""
Url scanner module to work with urls/domains/ips.
"""
import json
import socket
import urllib
from urllib.parse import urlparse

import requests

from .config import Config


class IPQS:
    """
    IP Quality Score class used to send request to IPQualityScore API and get results about url.
    """

    key = Config.IPQS_SECRET_KEY  # API SECRET KEY

    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
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

def get_ip(url: str) -> str:
    """
    Input url, output ip of url.
    """
    pass
    # ip_address = socket.gethostbyname(url)
    # return ip_address
