"""
Url scanner module to work with urls/domains/ips.
"""
import json
import requests
import urllib
from urllib.parse import urlparse

from config import DevelopmentConfig


class IPQS:
    """
    IP Quality Score class used to send request to IPQualityScore API and get results about url.
    """

    key = DevelopmentConfig.IPQS_SECRET_KEY  # API SECRET KEY

    def malicious_url_scanner_api(self, url: str, vars: dict = {}) -> dict:
        url = "https://www.ipqualityscore.com/api/json/url/%s/%s" % (
            self.key,
            urllib.parse.quote_plus(url),
        )
        scan_result = requests.get(url, params=vars)
        return json.loads(scan_result.text)


def get_domain(url: str) -> str:
    """
    Input url, output domain of url.
    """
    parsed_url = urlparse(url)
    return parsed_url.netloc
