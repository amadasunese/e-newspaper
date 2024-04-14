from flask import current_app, Blueprint, send_from_directory, abort, request, send_from_directory, render_template, jsonify, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from src.accounts.models import db, User, Newspaper, Subscription
from werkzeug.utils import secure_filename
import os
from flask_login import login_required, current_user, login_user, logout_user
from config import Config
import fitz  # PyMuPDF
from datetime import datetime
from flask_cors import CORS, cross_origin
from flask import session
from src.utils.decorators import logout_required, check_is_confirmed, check_is_subscribed, require_subscription, requires_subscription_to_newspaper
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from paystackapi.transaction import Transaction

from paystackapi.paystack import Paystack
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from forms import LoginForm, SignUpForm, EditUserForm, UploadNewspaperForm, ContactForm, ResetPasswordForm, ResetPasswordRequestForm
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import smtplib
from flask import send_file


from src.accounts.token import generate_confirmation_token, confirm_token

from config import send_email, send_feedback, send_password_reset_email

main = Blueprint('main', __name__)

@main.route('/')
def index():
    newspapers = Newspaper.query.all()
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
    return render_template('login.html', newspapers=newspapers, form=form)

load_dotenv()
PAYSTACK_SECRET_KEY = os.environ.get('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.environ.get('PAYSTACK_PUBLIC_KEY')
paystack = Paystack(secret_key=PAYSTACK_SECRET_KEY)


###################
# Error handling  #
###################
@main.app_errorhandler(404)
def page_not_found(e):
    if request.path.startswith('/api/'):
        return jsonify(error='Not found'), 404
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    if request.path.startswith('/api/'):
        return jsonify(error='Internal server error'), 500
    return render_template('500.html'), 500

@main.app_errorhandler(401)
def unauthorized(e):
    flash('You need to be logged in to access this page.', 'warning')
    return redirect(url_for('main.login'))



######################################
#         User management            #
######################################

@main.route('/register', methods=['GET', 'POST'])
# @logout_required
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password)

        new_user = User(name=name, username=username, password=hashed_password, email=email)

        try:
            db.session.add(new_user)
            db.session.commit()
            token = generate_confirmation_token(email)
            confirm_url = url_for("main.confirm_email", token=token, _external=True)
            html = render_template("confirm_email.html", confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(email, subject, html)
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('main.login'))


        except IntegrityError:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html')



@main.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.is_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('main.index'))


@main.route("/inactive")
@login_required
def inactive():
    if current_user.is_confirmed:
        return redirect(url_for("core.newspapers"))
    return render_template("inactive.html")


@main.route("/resend")
@login_required
def resend_confirmation():
    if current_user.is_confirmed:
        flash("Your account has already been confirmed.", "success")
        return redirect(url_for("core.newspapers"))
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for("main.confirm_email", token=token, _external=True)
    html = render_template("confirm_email.html", confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash("A new confirmation email has been sent.", "success")
    return redirect(url_for("inactive"))


@main.route('/login', methods=['GET', 'POST'])
@logout_required
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and check_password_hash(user.password, form.password.data):
                login_user(user)
                next_page = request.args.get('next')
                if user.is_admin:
                    session['is_admin'] = True
                    flash('Admin login successful', 'success')
                    return redirect(next_page or url_for('main.dashboard'))
                else:
                    session['is_admin'] = False
                    flash('Login successful', 'success')
                    return redirect(next_page or url_for('main.newspapers'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        return render_template('login.html', title='Login', form=form)
    except Exception as e:
        current_app.logger.error(f"An error occurred during login: {e}")
        flash('An unexpected error occurred. Please try again.', 'danger')
        return redirect(url_for('main.login'))


# mail = Mail()
# def send_password_reset_email(user):

#     """Initialize the serializer with the app's secret key"""
#     serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

#     """Generate a token"""
#     token = serializer.dumps(user.email, salt='password-reset-salt')

#     """Create the password reset email"""
#     msg = Message('Reset Your Password',
#                   sender=current_app.config["MAIL_DEFAULT_SENDER"],
#                   recipients=[user.email])

#     """Email body with the link to reset password"""
#     msg.body = (
#         "To reset your password, visit the following link: "
#         f"{url_for('main.reset_password', token=token, _external=True)}"
#     )

#     # Send the email
#     mail.send(msg)

@main.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """Process password reset request
    """
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Password reset email sent if your email is in our system.')
        return redirect(url_for('main.login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Initialize the serializer with the app's secret key"""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('main.reset_password_request'))

    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('main.reset_password_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        """Update user's password"""
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('main.login'))
    return render_template('reset_password.html',
                           title='Reset Password', form=form, token=token)



@main.route('/logout')
# @logout_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@main.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
# @login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access. Admins only.', 'danger')
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)

    if form.validate_on_submit():
        user.name = form.name.data
        user.username = form.username.data
        db.session.commit()
        flash('User has been updated.', 'success')
        return redirect(url_for('main.admin'))

    return render_template('edit_user.html', form=form, user=user)


@main.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
# @login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access. Admins only.', 'danger')
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'warning')
        return redirect(url_for('main.admin'))

    db.session.delete(user)
    db.session.commit()
    flash('User has been successfully deleted.', 'success')
    return redirect(url_for('main.admin'))


@main.route('/profile')
@login_required
def profile():
    user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()

    return render_template('profile.html', user=current_user, user_subscriptions=user_subscriptions)


######################################
# Newspaper pdf upload and thumbnai #
######################################

def create_thumbnail(pdf_path, thumbnail_path):
    doc = fitz.open(pdf_path)
    page = doc.load_page(0)
    pix = page.get_pixmap()
    pix.save(thumbnail_path)

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@main.route('/upload', methods=['GET', 'POST'])
# @login_required
def upload_file():
    form = UploadNewspaperForm()

    if form.validate_on_submit():
        file = form.pdf_file.data
        filename = secure_filename(file.filename)
        pdf_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(pdf_path)

        # Generate thumbnail
        thumbnail_filename = 'thumbnail_' + filename + '.png'
        thumbnail_path = os.path.join(current_app.config['UPLOAD_FOLDER'], thumbnail_filename)
        create_thumbnail(pdf_path, thumbnail_path)

        new_paper = Newspaper(
            title=form.title.data,
            pdf_file=filename,
            publication_date=form.publication_date.data,
            thumbnail=thumbnail_filename
        )
        db.session.add(new_paper)
        db.session.commit()

        flash('Newspaper uploaded successfully!', 'success')
        return redirect(url_for('main.newspapers'))
    else:
        for _, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')

    return render_template('upload.html', form=form)

@main.route('/delete_newspaper/<int:newspaper_id>', methods=['POST'])
# @login_required
def delete_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    db.session.delete(newspaper)
    db.session.commit()
    flash('Newspaper deleted successfully.', 'success')
    return redirect(url_for('main.newspapers'))


######################################
#   Admin routes and dashboard       #
######################################

@main.route('/admin')
# @login_required
def admin():
    if not current_user.is_admin:
        flash('Unauthorized access. Admins only.', 'danger')
        return redirect(url_for('main.login'))

    users = User.query.all()
    return render_template('admin.html', current_users=users)


# @main.route('/dashboard')
# # @login_required
# def dashboard():
#     user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
#     return render_template('dashboard.html', current_user=current_user, user_subscriptions=user_subscriptions)


# @main.route('/dashboard')
# @login_required
# def dashboard():
#     user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    
#     subscription = Subscription.query.get(subscription_id)

#     # Fetching total subscribers
#     total_subscribers = len(set(subscription.user_id for subscription in Subscription.query.all()))
    
#     # Fetching total amount earned, considering None values
#     total_amount_earned = sum(subscription.amount for subscription in Subscription.query.all() if subscription.amount is not None)
    
#     return render_template('dashboard.html', current_user=current_user,
#                            user_subscriptions=user_subscriptions,
#                            total_subscribers=total_subscribers,
#                            total_amount_earned=total_amount_earned)

# @main.route('/dashboard')  # Add subscription_id to the route
# @login_required
# def dashboard(subscription_id): # subscription_id=None  Make subscription_id optional

#     subscription = Subscription.query.get(subscription_id)
#     user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    
#     # subscription = None  # Initialize subscription as None
#     # # if subscription_id:  # Check if subscription_id is provided
#     # #     subscription = Subscription.query.get(subscription_id)
    
#     # Fetching total subscribers
#     total_subscribers = len(set(subscription.user_id for subscription in Subscription.query.all()))
    
#     # Fetching total amount earned, considering None values
#     total_amount_earned = sum(subscription.amount for subscription in Subscription.query.all() if subscription.amount is not None)
    
#     return render_template('dashboard.html', current_user=current_user,
#                            user_subscriptions=user_subscriptions,
#                            total_subscribers=total_subscribers,
#                            total_amount_earned=total_amount_earned,
#                            subscription=subscription)  # Pass subscription to the template


# @main.route('/dashboard/<int:subscription_id>')
# @login_required
# def dashboard(subscription_id):
#     user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    
#     # Fetching total subscribers
#     total_subscribers = len(set(subscription.user_id for subscription in Subscription.query.all()))
    
#     # Fetching total amount earned, considering None values
#     total_amount_earned = sum(subscription.amount for subscription in Subscription.query.all() if subscription.amount is not None)
    
#     # Fetch subscription details if subscription_id is provided
#     subscription = None
#     if subscription_id is not None:
#         subscription = Subscription.query.get(subscription_id)
    
#     return render_template('dashboard.html', current_user=current_user,
#                            user_subscriptions=user_subscriptions,
#                            total_subscribers=total_subscribers,
#                            total_amount_earned=total_amount_earned,
#                            subscription=subscription)

@main.route('/dashboard')
@login_required
def dashboard():
    user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    
    # Fetching total subscribers
    total_subscribers = len(set(subscription.user_id for subscription in Subscription.query.all()))
    
    # Fetching total amount earned, considering None values
    total_amount_earned = sum(subscription.amount for subscription in Subscription.query.all() if subscription.amount is not None)
    
    # Fetch subscription ID or calculate it here
    # For example:
    # Fetch subscription ID for the current user
    subscription_id = Subscription.query.filter_by(user_id=current_user.id).first().id
    # subscriptions = Subscription.query.filter_by(subscription_id=subscription_id).first()
    # subscription = Subscription.query.get(subscription_id)
    # subscription_id = Subscription.query.get_subscription_id()  # Replace with your logic to obtain subscription ID
    
    return render_template('dashboard.html', current_user=current_user,
                           user_subscriptions=user_subscriptions,
                           total_subscribers=total_subscribers,
                           total_amount_earned=total_amount_earned,
                           subscription=subscription_id)  # Pass subscription ID to template




######################################
# Newspaper subscription routes      #
######################################

@main.route('/subscribe_and_pay/<int:newspaper_id>')
@login_required
def subscribe_and_pay(newspaper_id):
    newspapers = Newspaper.query.get_or_404(newspaper_id)
    return render_template('payment.html', newspaper=newspapers)


@main.route('/newspapers')
@login_required
@check_is_confirmed
def newspapers():
    newspapers = Newspaper.query.all()
    user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    subscribed_newspapers = [sub.newspaper_id for sub in user_subscriptions]
    return render_template('newspapers.html', newspapers=newspapers, subscribed_newspapers=subscribed_newspapers)


@main.route('/read_newspaper/<int:newspaper_id>')
@login_required
def read_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)

    pdf_url = url_for('static', filename='pdfs/' + newspaper.pdf_file)
    return render_template('view_pdf.html', newspaper=newspaper, pdf_url=pdf_url)


@main.route('/payment/<int:newspaper_id>', methods=['GET', 'POST'])
@login_required
def payment(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    amount = 10000
    email = current_user.email

    response = Transaction.initialize(amount=str(amount), email=email)
    print('this is the response', response)
    new_subscription = Subscription(
        user_id=current_user.id,
        newspaper_id=newspaper.id,
        active=True,
        subscription_date=datetime.utcnow(),
        payment_id=response['data'].get('reference')
    )
    db.session.add(new_subscription)
    db.session.commit()

    a_url = response['data']['authorization_url']
    return redirect(a_url)

    # Handle GET request by rendering the payment form template
    # return render_template('payment_form.html', newspaper=newspaper, amount=amount)


@main.route('/payment_verification', methods=['GET', 'POST'])
def payment_verification():
    if request.method == 'POST':
        data = request.json
        if data is None:
            return jsonify({'message': 'Request must be JSON with Content-Type application/json'}), 400

    paramz = request.args.get('trxref', 'None')

    details = Transaction.verify(reference=paramz)
    status = details['data']['status']

    subscription = Subscription.query.filter_by(payment_id=paramz).first()
    print('this is subscription id', subscription)

    if status == 'success':
        if subscription:
            subscription.active = True
            db.session.commit()
            # return redirect(url_for('main.dashboard'))
    else:
        print(f"Payment verification failed with status: {status}")

    return jsonify({'message': 'Payment verification failed'}), 400



# @main.route('/view_latest_issues')
# @cross_origin()
# # @require_subscription
# @login_required
# def view_latest_issues():
#     try:
#         newspapers = Newspaper.query.order_by(Newspaper.publication_date.desc()).all()
#     except SQLAlchemyError as e:
#         main.logger.error(f"Database error occurred: {str(e)}")
#         flash('An error occurred while fetching the latest issues. Please try again later.', 'error')
#         return redirect(url_for('main.index'))

#     return render_template('view_latest_issue.html', newspapers=newspapers)


# @main.route('/subscribe/<int:newspaper_id>', methods=['GET', 'POST'])
# @login_required
# def subscribe(newspaper_id):
#     newspaper = Newspaper.query.get_or_404(newspaper_id)
#     return render_template('subscription.html', newspaper=newspaper, user=current_user)



@main.route('/manage_subscriptions')
# @login_required
# @check_is_confirmed
def manage_subscriptions():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('main.login'))

    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    return render_template('manage_subscription.html', subscriptions=subscriptions)


####################
# Contact routes #
####################

@main.route('/contact', methods=['GET', 'POST'])
# @login_required
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data

        template = f"""
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Message:</strong> {message}</p>
        """

        try:
            send_feedback(to=current_app.config["MAIL_DEFAULT_SENDER"], subject="Contact Form Submission", template=template)
            flash('Your message has been sent. Thank you!', 'success')
            return redirect(url_for('main.contact'))
        except Exception as e:
            flash('An error occurred while sending the feedback.', 'danger')
            current_app.logger.error(f"Error sending feedback: {e}")

    return render_template('contact.html', form=form)

@main.route('/advertising')
def advertising():
    return render_template('advertising.html')


# # Downloading newspapers

@main.route('/download_newspaper/<int:newspaper_id>')
@login_required
def download_newspaper(newspaper_id):
    # Fetch the newspaper details from the database
    newspaper = Newspaper.query.get(newspaper_id)
    if not newspaper:
        abort(404, description="Newspaper not found.")

    # Check if the current user is subscribed to the newspaper
    subscription = Subscription.query.filter_by(user_id=current_user.id, newspaper_id=newspaper_id, active=True).first()
    if not subscription:
        flash('You are not subscribed to this edition.', 'warning')
        return redirect(url_for('main.view_latest_issues'))

    # Check if the file exists
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], newspaper.pdf_file)
    if not os.path.exists(file_path):
        abort(404, description="File not found.")

    # Serve the file for download
    return send_from_directory(directory=current_app.config['UPLOAD_FOLDER'], path=newspaper.pdf_file, as_attachment=True)




@main.route('/transaction/<int:subscription_id>')
def transaction(subscription_id):
    subscription = Subscription.query.get(subscription_id)

    return render_template('transaction.html', subscription=subscription)



# @main.route('/transactions')
# def transactions():
#     subscriptions = Subscription.query.all()
#     user = User.query.filter_by(user.name).firstl()
#     return render_template('transaction.html', user=user, subscriptions=subscriptions)



@main.route('/transactions')
def transactions():
    # Fetching subscriptions
    subscriptions = Subscription.query.all()
    
    # Extracting user IDs from subscriptions
    user_ids = {subscription.user_id for subscription in subscriptions}
    
    # Fetching users who have subscribed
    users_subscribed = User.query.filter(User.id.in_(user_ids)).all()
    
    return render_template('transaction.html', users=users_subscribed, subscriptions=subscriptions)


# @main.route('/download_newspaper/<int:newspaper_id>')
# @login_required
# def download_newspaper(newspaper_id):
#     # Assuming `get_newspaper_by_id` is a method that fetches the newspaper details
#     newspaper = get_newspaper_by_id(newspaper_id)
    
#     if not newspaper:
#         flash('Newspaper not found.', 'error')
#         return redirect(url_for('index'))

#     # Assuming `user_subscribed_to_newspaper` checks if the current user is subscribed
#     if not user_subscribed_to_newspaper(current_user.id, newspaper_id):
#         flash('You are not subscribed to this newspaper.', 'error')
#         return redirect(url_for('index'))

#     # Assuming the PDFs are stored in a directory within the static folder
#     pdf_directory = '/statci' + '/pdfs/'    # 'static/' + '/pdfs/'
#     pdf_filename = newspaper.pdf_path  # This should contain the filename of the PDF

#     try:
#         # Send the file directly for download
#         return send_from_directory(directory=pdf_directory, path=pdf_filename, as_attachment=True)
#     except FileNotFoundError:
#         flash('File not found.', 'error')
#         return redirect(url_for('index'))

# @main.route('/download_newspaper/<int:newspaper_id>')
# @login_required
# def download_newspaper(newspaper_id):
    
#     # Assuming a function that fetches newspaper details from the DB
#     # newspaper = get_newspaper_by_id(newspaper_id)
#     newspaper = Newspaper.query.get(newspaper_id)
#     print('this is the id', newspaper)
    
#     if not newspaper:
#         flash('Newspaper not found.', 'error')
#         return redirect(url_for('main.newspapers'))

#     # Ensure the user is subscribed to the newspaper
#     if not user_subscribed_to_newspaper(current_user.id, newspaper_id):
#         flash('You are not subscribed to this newspaper.', 'error')
#         return redirect(url_for('main.newspapers'))

#     # Construct the full path to the PDF
#     pdf_directory = os.path.join(current_app.static, 'pdfs')
#     print('this is the directory', pdf_directory)
#     pdf_filename = newspaper.pdf_file
#     print('this is the pdf file name', pdf_filename)

#     # Verify the PDF file exists before attempting to send it
#     pdf_path = os.path.join(pdf_directory, pdf_filename)
#     if not os.path.exists(pdf_path):
#         flash('PDF file does not exist.', 'error')
#         return redirect(url_for('main.newspapers'))

#     # Correctly setting MIME type and headers for PDF download
#     try:
#         return send_from_directory(directory=pdf_directory, path=pdf_filename, as_attachment=True)
#     except FileNotFoundError:
#         flash('File not found.', 'error')
#         return redirect(url_for('main.newspapers'))
    
    
# def get_newspaper_by_id(newspaper_id):
#     # Placeholder for database query
#     Newspaper.query.get(newspaper_id)
#     pass

# def user_subscribed_to_newspaper(user_id, newspaper_id):
#     # Placeholder for subscription check
#     Subscription.query.filter_by(user_id=user_id, newspaper_id=newspaper_id).first() is not None
#     pass