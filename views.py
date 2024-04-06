from flask import current_app, Blueprint, abort, request, send_from_directory, render_template, jsonify, request, redirect, url_for, flash
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
from src.utils.decorators import check_is_subscribed, require_subscription, requires_subscription_to_newspaper
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from paystackapi.transaction import Transaction

from paystackapi.paystack import Paystack
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from forms import LoginForm, SignUpForm, EditUserForm, UploadNewspaperForm



main = Blueprint('main', __name__)

@main.route('/')
def index():
    newspapers = Newspaper.query.all()
    return render_template('newspapers.html', newspapers=newspapers)


load_dotenv()
PAYSTACK_SECRET_KEY = os.environ.get('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.environ.get('PAYSTACK_PUBLIC_KEY')
paystack = Paystack(secret_key=PAYSTACK_SECRET_KEY)


###################
# Error handling  #
###################
@main.app_errorhandler(404)
def page_not_found(e):
    # Respond differently if it's an API call
    if request.path.startswith('/api/'):
        return jsonify(error='Not found'), 404
    return render_template('404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
    # Respond differently if it's an API call
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
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('main.login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
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


@main.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@main.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
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
@login_required
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
@login_required
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
        return redirect(url_for('main.index'))
    else:
        for _, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')

    return render_template('upload.html', form=form)

@main.route('/delete_newspaper/<int:newspaper_id>', methods=['POST'])
@login_required
def delete_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    db.session.delete(newspaper)
    db.session.commit()
    flash('Newspaper deleted successfully.', 'success')
    return redirect(url_for('main.view_latest_issues'))


######################################
#   Admin routes and dashboard       #
######################################

@main.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Unauthorized access. Admins only.', 'danger')
        return redirect(url_for('main.login'))
    
    users = User.query.all()
    return render_template('admin.html', current_users=users)


@main.route('/dashboard')
@login_required
def dashboard():
    # Query the current user's subscriptions
    user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', current_user=current_user, user_subscriptions=user_subscriptions)


######################################
# Newspaper subscription routes      #
######################################

@main.route('/subscribe_and_pay/<int:newspaper_id>')
@login_required
def subscribe_and_pay(newspaper_id):
    newspapers = Newspaper.query.get_or_404(newspaper_id)
    return render_template('payment.html', newspaper=newspapers)


# @main.route('/newspapers')
# @login_required
# def newspapers():
#     newspapers = Newspaper.query.all()
#     user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
#     return render_template('newspapers.html', newspapers=newspapers, user_subscriptions=user_subscriptions)

# @main.route('/newspapers')
# def newspapers():
#     newspapers = Newspaper.query.all()
#     user_subscriptions = current_user.subscribed_newspapers.split(',') if current_user.is_authenticated else []
#     return render_template('newspapers.html', newspapers=newspapers, user_subscriptions=user_subscriptions)


@main.route('/newspapers')
@login_required
def newspapers():
    newspapers = Newspaper.query.all()
    user_subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()

    # Extract newspaper IDs from subscriptions
    subscribed_newspaper_ids = [sub.newspaper_id for sub in user_subscriptions]
    print('this is the subscribed newspaper ids', subscribed_newspaper_ids)

    #Query newspapers with the extracted IDs
    subscribed_newspapers = Newspaper.query.filter(Newspaper.id.in_(subscribed_newspaper_ids)).all()
    print('this is the subscribed newspaper', subscribed_newspapers)

    return render_template('newspapers.html', newspapers=newspapers, subscribed_newspapers=subscribed_newspapers, user_subscriptions=user_subscriptions)



@main.route('/read_newspaper/<int:newspaper_id>')
@login_required
def read_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)

    pdf_url = url_for('static', filename='pdfs/' + newspaper.pdf_file)
    return render_template('view_pdf.html', newspaper=newspaper, pdf_url=pdf_url)


# @main.route('/payment/<int:newspaper_id>', methods=['GET', 'POST'])
# @login_required
# def payment(newspaper_id):
#     newspaper = Newspaper.query.get_or_404(newspaper_id)
#     amount = 10000
#     email = current_user.email
#     if request.method == 'POST':
#         response = Transaction.initialize(amount=str(amount), email=email)
#         print('this is the response', response)

#         new_subscription = Subscription(
#             user_id=current_user.id,
#             newspaper_id=newspaper.id,
#             active=True,
#             subscription_date=datetime.utcnow(),
#             payment_id=response['data'].get('reference')
#         )
#         db.session.add(new_subscription)
#         db.session.commit()

#         # Redirect the user to the payment authorization URL
#         a_url = response['data']['authorization_url']
#         return redirect(a_url)

    #     flash('Your subscription has been successful!', 'success')
    #     return redirect(url_for('main.dashboard'))

    # return render_template('payment_form.html', newspaper=newspaper, amount=amount)


@main.route('/payment/<int:newspaper_id>', methods=['GET', 'POST'])
@login_required
def payment(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    amount = 10000
    email = current_user.email
    
    response = Transaction.initialize(amount=str(amount), email=email)
    print('this is the response', response)
    # if request.method == 'POST':
    #     response = Transaction.initialize(amount=str(amount), email=email)
    #     print('this is the response', response)

    new_subscription = Subscription(
        user_id=current_user.id,
        newspaper_id=newspaper.id,
        active=True,
        subscription_date=datetime.utcnow(),
        payment_id=response['data'].get('reference')
    )
    db.session.add(new_subscription)
    db.session.commit()

        # Redirect the user to the payment authorization URL
    a_url = response['data']['authorization_url']
    return redirect(a_url)
    
    # Handle GET request by rendering the payment form template
    # return render_template('payment_form.html', newspaper=newspaper, amount=amount)


# @main.route('/process_payment', methods=['GET', 'POST'])
# @login_required
# def process_payment():
#     # Fetch newspaper_id from the query parameters
#     newspaper_id = request.args.get('newspaper_id')
#     if not newspaper_id:
#         flash("No newspaper selected for subscription.", "error")
#         return redirect(url_for('select_newspaper'))

#     # Find the corresponding Newspaper instance in the database
#     newspaper = Newspaper.query.get(newspaper_id)
#     if not newspaper:
#         flash("Selected newspaper does not exist.", "error")
#         return redirect(url_for('select_newspaper'))

#     amount = 1000
  
#     # Simulate initializing a payment transaction
#     response = Transaction.initialize(amount=str(amount), email=current_user.email)
#     if not response or 'data' not in response or 'reference' not in response['data']:
#         flash("Failed to initialize payment.", "error")
#         return redirect(url_for('select_newspaper'))

#     # Create a new Subscription instance
#     create_subscription_instance = Subscription(
#         user_id=current_user.id,
#         amount=amount,
#         newspaper_id=newspaper.id,
#         active=True,
#         subscription_date=datetime.utcnow(),
#         payment_id=response['data'].get('reference')
#     )

#     db.session.add(create_subscription_instance)
#     db.session.commit()

#     # Redirect the user to the payment authorization URL
#     a_url = response['data']['authorization_url']
#     return redirect(a_url)



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
            # return redirect(url_for('core.dashboard'))      
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

# @main.route('/cancel_subscription/<int:id>', methods=['GET'])
# @login_required
# def cancel_subscription(id):
#     subscription = Subscription.query.filter_by(id=id, user_id=current_user.id).first()
#     if subscription:
#         subscription.active = False
#         db.session.commit()
#         flash('Subscription canceled successfully.', 'success')
#     else:
#         flash('Subscription not found.', 'error')
#     return redirect(url_for('main.manage_subscription'))


# @main.route('/renew_subscription/<int:id>', methods=['GET'])
# @login_required
# def renew_subscription(id):
#     subscription = Subscription.query.filter_by(id=id, user_id=current_user.id).first()
#     if subscription:
#         subscription.active = True
#         db.session.commit()
#         flash('Subscription renewed successfully.', 'success')
#     else:
#         flash('Subscription not found.', 'error')
#     return redirect(url_for('views.manage_subscription'))


@main.route('/manage_subscriptions')
# @login_required
def manage_subscriptions():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('main.login'))

    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    return render_template('manage_subscription.html', subscriptions=subscriptions)





####################
# Users Management #
####################









