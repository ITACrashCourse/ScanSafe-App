from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func


db = SQLAlchemy()

class Role(db.Model):
    __tablename__ = "roles"

    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String)
    role_description = db.Column(db.String)

    def __init__(self,role_id, role_name, role_description):
        self.role_id = role_id
        self.role_name = role_name
        self.role_description = role_description

    def __repr__(self) -> str:
        return f"{self.role_name} {self.role_description}"


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False )
    role_id = db.Column(db.String, db.ForeignKey("roles.role_id"))
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, onupdate=func.now())
    active = db.Column(db.Boolean)


class IP_address(db.Model):
    __tablename__ = "ip_address"

    ip_id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False)
    record_created_at = db.Column(db.DateTime, server_default=func.now())
    record_updated_at = db.Column(db.DateTime, onupdate=func.now())
    server = db.Column(db.String(64))
    category = db.Column(db.String(64))
    unsafe = db.Column(db.Boolean)
    risk_score = db.Column(db.Integer)
    suspicious = db.Column(db.Boolean)
    malware = db.Column(db.Boolean)
    phising = db.Column(db.Boolean)
    spamming = db.Column(db.Boolean)
    parking = db.Column(db.Boolean)
    dns_server = db.Column(db.Boolean)
    dns_valid = db.Column(db.Boolean)
    urls = db.relationship("URL", backref='ip_address')


class Domains(db.Model):
    __tablename__ = "domains"

    domain_id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(64), nullable=False)
    record_created_at = db.Column(db.DateTime, server_default=func.now())
    record_updated_at = db.Column(db.DateTime, onupdate=func.now())
    urls = db.relationship("URL", backref='domain')

class URL(db.Model):
    __tablename__ = "url"

    url_id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.domain_id"))
    ip_id = db.Column(db.Integer, db.ForeignKey("ip_address.ip_id"))
    url = db.Column(db.String(64))
    record_created_at = db.Column(db.DateTime, server_default=func.now())
    last_scan = db.Column(db.DateTime, server_default=func.now())
    added_by = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    search_counter = db.Column(db.Integer)
    safety_status = db.Column(db.String(64))
