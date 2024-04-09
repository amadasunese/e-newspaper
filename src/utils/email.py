from flask_mail import Mail, Message
from flask import url_for
from config import Config
from itsdangerous import URLSafeTimedSerializer


mail = Mail()

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

def send_feedback(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# def send_password_reset_email(user):
#     """Password reset email
#     """
#     token = s.dumps(user.email, salt='password-reset-salt')
#     msg = Message('Reset Your Password', sender=current_app.config["MAIL_DEFAULT_SENDER"],
#                   recipients=[user.email])
#     msg.body = (
#         f"To reset your password, visit the following link: "
#         f"{url_for('main.reset_password', token=token, _external=True)}"
#     )
#     mail.send(msg)


def send_password_reset_email(user):
    # Generate a token
    token = s.dumps(user.email, salt='password-reset-salt')

    # Create the password reset email
    msg = Message('Reset Your Password', 
                  sender=config["MAIL_DEFAULT_SENDER"], 
                  recipients=[user.email])

    # Email body with the link to reset password
    msg.body = (
        "To reset your password, visit the following link: "
        f"{url_for('main.reset_password', token=token, _external=True)}"
    )
    
    # Send the email
    mail.send(msg)