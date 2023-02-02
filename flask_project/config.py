"""config.py - """


class Config(object):
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    DEBUG = True
    IPQS_SECRET_KEY = ""  # Put here your ip quality score secret key.


class TestingConfig(Config):
    TESTING = True
