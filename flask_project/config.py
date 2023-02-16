"""config.py - """
import os
import re

from dotenv import load_dotenv

load_dotenv()


def get_ipqs_secret_key():
    """
    Retrieve IPQS API secret key from the .env. If not exception if raised.
    Returns:
        - str: ipqs api secret key.
    """
    ipqs_secret_key = os.environ.get("IPQS_SECRET_KEY")
    if not ipqs_secret_key:
        raise Exception(
            "IP Quality Score API secret key environment variable is not set or is empty."
        )
    return ipqs_secret_key

def get_database_uri():
    sqlalchemy_database_uri = os.environ.get("DATABASE_URL")
    if not sqlalchemy_database_uri:
        raise Exception(
            "No database connection!"
        )
    return sqlalchemy_database_uri


def get_database_uri():
    """
    Retrieve database_url from the .env. If not exception if raised.
    Returns:
        - str: database_url.
    """
    sqlalchemy_database_uri = os.environ.get("DATABASE_URL")
    if not sqlalchemy_database_uri:
        raise Exception("No database configuration found!")
    return sqlalchemy_database_uri


class Config(object):
    """
    Base configuration for the Flask app.
    """
    DEBUG = False
    TESTING = False
    IPQS_URL = "https://www.ipqualityscore.com/api/json/url/%s/%s"
    IPQS_SECRET_KEY = get_ipqs_secret_key()
    HOSTNAME = os.environ.get("HOSTNAME", "localhost")
    PORT = os.environ.get("PORT", "5000")


class DevelopmentConfig(Config):
    """
    Development environment configuration for Flask app.
    """
    DEVELOPMENT = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = get_database_uri()


#TODO
class TestingConfig(Config):
    """
    Testing environment configuration for Flask app.
    """
    TESTING = True


class RegularExpression(Config):
    """
    Regular expression patterns
    """
    REGEX_DOMAIN = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')