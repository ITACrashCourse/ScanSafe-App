"""
flask_project

Initialization and setup of the Flask Application.
    - app (Flask)
    - db (SQLAlchemy)
Components:
    - DevelopmentConfig: The configuration class for the dev environment.
    - routes: endpoint definitions.
    - models: database models.
"""
from flask import Flask
from flask_smorest import Api
from .config import DevelopmentConfig
from .models import db
from .routes import blp

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
db.init_app(app)
with app.app_context():
    db.create_all()

api=Api(app)
api.register_blueprint(blp)

from flask_project import routes, models
