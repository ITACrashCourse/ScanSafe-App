from flask import Flask
from .config import DevelopmentConfig
from .models import db

app = Flask(__name__)
app.config.from_object(DevelopmentConfig)
db.init_app(app)






from flask_project import routes, models
