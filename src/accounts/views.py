# from flask import Blueprint, flash, redirect, render_template, request, url_for, session
# from flask_login import login_required, login_user, logout_user, current_user
# from src import bcrypt, db
# from src.accounts.models import User
# from forms import ContactForm, ResetPasswordForm, ResetPasswordRequestForm
# from src.utils.decorators import logout_required
# from src.accounts.token import confirm_token, generate_token
# from src.utils.email import send_email


# from datetime import datetime
# from markupsafe import Markup
# from flask_mail import Message, Mail
# from src import app
# import smtplib
# from itsdangerous import URLSafeTimedSerializer


# import io
# import os

# main = Blueprint("main", __name__)


# # Configure your email settings
# EMAIL_HOST = 'smtp.gmail.com'
# EMAIL_PORT = 587
# EMAIL_HOST_USER = 'lessonplanai@gmail.com'
# EMAIL_HOST_PASSWORD = 'kyvy fwml epob tcta'
# RECIPIENT_ADDRESS = 'lessonplanai@gmail.com'
# mail = Mail(app)


# @main.route("/confirm/<token>")
# @login_required
# def confirm_email(token):
#     if current_user.is_confirmed:
#         flash("Account already confirmed.", "success")
#         return redirect(url_for("newspaper"))
#     email = confirm_token(token)
#     user = User.query.filter_by(email=current_user.email).first_or_404()
#     if user.email == email:
#         user.is_confirmed = True
#         user.confirmed_on = datetime.now()
#         db.session.add(user)
#         db.session.commit()
#         flash("You have confirmed your account. Thanks!", "success")
#     else:
#         flash("The confirmation link is invalid or has expired.", "danger")
#     return redirect(url_for("main.newspaper"))


# @main.route("/inactive")
# @login_required
# def inactive():
#     if current_user.is_confirmed:
#         return redirect(url_for("main.newspaper"))
#     return render_template("main/inactive.html")

# @main.route("/resend")
# @login_required
# def resend_confirmation():
#     if current_user.is_confirmed:
#         flash("Your account has already been confirmed.", "success")
#         return redirect(url_for("core.newspaper"))
#     token = generate_token(current_user.email)
#     confirm_url = url_for("main.confirm_email", token=token, _external=True)
#     html = render_template("main/confirm_email.html", confirm_url=confirm_url)
#     subject = "Please confirm your email"
#     send_email(current_user.email, subject, html)
#     flash("A new confirmation email has been sent.", "success")
#     return redirect(url_for("main.inactive"))




# @main.route('/contact', methods=['GET', 'POST'])
# @login_required
# def contact():
#     form = ContactForm()

#     if form.validate_on_submit():
#         """
#         Handle the form submission, e.g., send an email
#         """
#         name = form.name.data
#         email = form.email.data
#         message = form.message.data
        
#         """
#         Process the data as needed
#         """
#         email_message = f"Subject: Feedback from {name}\n\nFrom: {email}\n\nMessage: {message}"

#         # Sending the email
#         try:
#             server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
#             server.ehlo()
#             server.starttls()
#             server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
#             server.sendmail(EMAIL_HOST_USER, RECIPIENT_ADDRESS, email_message)
#             server.close()
#             return 'Feedback sent successfully!'
#         except Exception as e:
#             return str(e)
#             return redirect(url_for('core.home'))

#     return render_template('contact.html', form=form)


# ###############################
# #   Password resent routes    #
# ##############################

# s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# def send_password_reset_email(user):
#     """Password reset email
#     """
#     token = s.dumps(user.email, salt='password-reset-salt')
#     msg = Message('Reset Your Password', sender='lessonplanai@gmail.com',
#                   recipients=[user.email])
#     msg.body = (
#         f"To reset your password, visit the following link: "
#         f"{url_for('accounts.reset_password', token=token, _external=True)}"
#     )
#     mail.send(msg)


# @main.route('/reset_password_request', methods=['GET', 'POST'])
# def reset_password_request():
#     """Process password reset request
#     """
#     form = ResetPasswordRequestForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             send_password_reset_email(user)
#         flash('Password reset email sent if your email is in our system.')
#         return redirect(url_for('main.login'))
#     return render_template('main/reset_password_request.html',
#                            title='Reset Password', form=form)


# @main.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     try:
#         email = s.loads(token, salt='password-reset-salt', max_age=3600)
#     except Exception:
#         flash('The password reset link is invalid or has expired.')
#         return redirect(url_for('accounts.reset_password_request'))

#     user = User.query.filter_by(email=email).first()
#     if user is None:
#         flash('Invalid user.')
#         return redirect(url_for('main.reset_password_request'))

#     form = ResetPasswordForm()
#     if form.validate_on_submit():
#         # Update user's password
#         user.password_hash = bcrypt.generate_password_hash(form.password.data)
#         db.session.commit()
#         flash('Your password has been reset.')
#         return redirect(url_for('main.login'))
#     return render_template('main/reset_password.html',
#                            title='Reset Password', form=form, token=token)

