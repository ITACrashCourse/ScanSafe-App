"""config.py - """
import os

from dotenv import load_dotenv

load_dotenv()


def get_ipqs_secret_key():
    ipqs_secret_key = os.environ.get("IPQS_SECRET_KEY")
    if not ipqs_secret_key:
        raise Exception(
            "IP Quality Score API secret key environment variable is not set or is empty."
        )
    return ipqs_secret_key


class Config(object):
    DEBUG = False
    TESTING = False
    IPQS_URL = "https://www.ipqualityscore.com/api/json/url/%s/%s"
    IPQS_SECRET_KEY = get_ipqs_secret_key()
    HOSTNAME = os.environ.get("HOSTNAME", "localhost")
    PORT = os.environ.get("PORT", "5000")


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
