import os
from flask_migrate import Migrate
from decouple import config
from flask_mail import Mail, Message
from flask import current_app
from flask import url_for
from itsdangerous import URLSafeTimedSerializer

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
    # URLSafeTimedSerializer = config('SECRET_KEY')

    # Flask app configuration
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'amadasunese@gmail.com'
    MAIL_PASSWORD = 'qxxo axga dzia jjsw'
    MAIL_DEFAULT_SENDER = 'amadasunese@gmail.com'

mail = Mail()

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

def send_feedback(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

def send_password_reset_email(user):

    """Initialize the serializer with the app's secret key"""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    """Generate a token"""
    token = serializer.dumps(user.email, salt='password-reset-salt')

    """Create the password reset email"""
    msg = Message('Reset Your Password',
                  sender=current_app.config["MAIL_DEFAULT_SENDER"],
                  recipients=[user.email])

    """Email body with the link to reset password"""
    msg.body = (
        "To reset your password, visit the following link: "
        f"{url_for('main.reset_password', token=token, _external=True)}"
    )

    # Send the email
    mail.send(msg)