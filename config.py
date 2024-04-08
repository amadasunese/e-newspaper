import os
from flask_migrate import Migrate
from decouple import config
# from app import app, db

class Config:
    SECRET_KEY = '17287727877878'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///newspaper.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/pdfs'

    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = config("SECRET_KEY", default="can-you-guess?")
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SECURITY_PASSWORD_SALT = config("SECURITY_PASSWORD_SALT", default="important")

    # Flask app configuration
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'amadasunese@gmail.com'
    MAIL_PASSWORD = 'qxxo axga dzia jjsw'
    MAIL_DEFAULT_SENDER = 'amadasunese@gmail.com'

