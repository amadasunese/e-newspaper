from flask import current_app, Blueprint, send_from_directory, render_template, jsonify, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from src.accounts.models import db, User, Newspaper, Subscription
from werkzeug.utils import secure_filename
import os
from flask_login import login_required, current_user, login_user
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



main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('dashboard.html',)


load_dotenv()
PAYSTACK_SECRET_KEY = os.environ.get('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.environ.get('PAYSTACK_PUBLIC_KEY')
paystack = Paystack(secret_key=PAYSTACK_SECRET_KEY)
# Error handling

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


@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('main.login'))
    return render_template('register.html')



@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # User's credentials are correct
            session['logged_in'] = True
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin

            return redirect(url_for('main.index'))
        else:
            flash('Invalid login credentials')
    
    return render_template('login.html')

# @main.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = User.query.filter_by(username=username).first()
        
#         # if user and user.check_password(password):
#         if user and check_password_hash(user.password, password):
#             if user.is_admin:
#                 # Redirect to admin dashboard or specific admin route
#                 return redirect(url_for('admin_dashboard'))
#             else:
#                 # Redirect to regular user homepage
#                 return redirect(url_for('main.index'))
#         else:
#             # Handle failed login (e.g., display error message)
#             return 'Invalid username/password'
#     return render_template('login.html') 


# @main.route('/login', methods=['GET', 'POST'])
# def login():
#     # Redirect already authenticated users
#     if current_user.is_authenticated:
#         return redirect(url_for('main.index'))

#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#         user = User.query.filter_by(username=username).first()

#         if user and check_password_hash(user.password, password):
#             # Use Flask-Login to handle the user session
#             login_user(user)

#             # Redirect to the intended page or to the index page
#             next_page = request.args.get('next')
#             return redirect(next_page or url_for('main.index'))
#         else:
#             flash('Invalid login credentials')
    
#     return render_template('login.html')


@main.route('/logout')
def logout():
    # Clear the session
    session.clear()
    
    # Or, if you're using specific keys:
    # session.pop('user_id', None)
    
    # Redirect to login page or home page
    return redirect(url_for('main.login'))

def create_thumbnail(pdf_path, thumbnail_path):
    doc = fitz.open(pdf_path)
    page = doc.load_page(0)
    pix = page.get_pixmap()
    pix.save(thumbnail_path)

ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        title = request.form.get('title', 'Default Title')
        publication_date = request.form.get('publication_date')
        if publication_date:
            publication_date = datetime.strptime(publication_date, '%Y-%m-%d')
        else:
            publication_date = datetime.utcnow()

        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            pdf_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(pdf_path)

            # Generate thumbnail
            thumbnail_filename = 'thumbnail_' + filename + '.png'
            thumbnail_path = os.path.join(current_app.config['UPLOAD_FOLDER'], thumbnail_filename)
            create_thumbnail(pdf_path, thumbnail_path)
            
            """# Save newspaper info including title, publication date,
            pdf filename, and thumbnail filename in DB
            """
            new_paper = Newspaper(title=title,
                                  pdf_file=filename,
                                  publication_date=publication_date,
                                  thumbnail=thumbnail_filename)
            db.session.add(new_paper)
            db.session.commit()

            flash('Newspaper uploaded successfully!')
            return redirect(url_for('main.index'))
        else:
            flash('File type not allowed')
    
    return render_template('upload.html')


# @main.route('/admin')
# def admin():
#     # Admin view logic here
#     users = User.query.all()
#     return render_template('admin.html', users=users)


@main.route('/admin')
def admin():
    # Check if the user is logged in and is an admin
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.login'))

    # Assuming User.query.all() fetches all user records
    users = User.query.all()
    return render_template('admin.html', users=users)



@main.route('/dashboard')
@login_required
def dashboard():
    current_user = User.query.all()
    newspaper = Newspaper.query.get_or_404(id)
    return render_template('dashboard.html', current_user=current_user, newspaper=newspaper)




@main.route('/cancel_subscription/<int:id>', methods=['GET'])
@login_required
def cancel_subscription(id):
    subscription = Subscription.query.filter_by(id=id, user_id=current_user.id).first()
    if subscription:
        subscription.active = False
        db.session.commit()
        flash('Subscription canceled successfully.', 'success')
    else:
        flash('Subscription not found.', 'error')
    return redirect(url_for('main.manage_subscription'))


@main.route('/renew_subscription/<int:id>', methods=['GET'])
@login_required
def renew_subscription(id):
    subscription = Subscription.query.filter_by(id=id, user_id=current_user.id).first()
    if subscription:
        subscription.active = True
        db.session.commit()
        flash('Subscription renewed successfully.', 'success')
    else:
        flash('Subscription not found.', 'error')
    return redirect(url_for('views.manage_subscription'))


# @main.route('/subscribe', methods=['GET', 'POST'])
# # @login_required
# def subscribe():
#     if request.method == 'POST':
#         newspaper_id = request.form.get('newspaper')
#         """Check if the user is already subscribed to this edition"""
#         existing_subscription = Subscription.query.filter_by(user_id=current_user.id, newspaper_id=newspaper_id).first()
#         if existing_subscription:
#             flash('You are already subscribed to this edition.', 'info')
#         else:
#             new_subscription = Subscription(user_id=current_user.id, newspaper_id=newspaper_id, active=True)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')
#         return redirect(url_for('main.view_latest_issues'))
    
#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers)

# @main.route('/subscribe', methods=['GET', 'POST'])
# @login_required  # Ensure this route is accessible only by authenticated users
# def subscribe():
#     if request.method == 'POST':
#         newspaper_id = request.form.get('newspaper')
#         # Check if the user is already subscribed to this newspaper
#         existing_subscription = Subscription.query.filter_by(user_id=current_user.id, newspaper_id=newspaper_id).first()
#         if existing_subscription:
#             flash('You are already subscribed to this newspaper.', 'info')
#         else:
#             # Create a new subscription
#             new_subscription = Subscription(user_id=current_user.id, newspaper_id=newspaper_id, active=True)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')
#         return redirect(url_for('main.view_latest_issues'))
    
#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers)

# @main.route('/subscribe', methods=['GET', 'POST'])
# def subscribe():
#     # Redirect users who are not logged in to the login page
#     if 'logged_in' not in session or not session['logged_in']:
#         flash('You need to be logged in to subscribe.', 'info')
#         return redirect(url_for('login'))

#     if request.method == 'POST':
#         newspaper_id = request.form.get('newspaper_id')
#         user_id = session.get('user_id')
#         print('this is the id number', newspaper_id)
#         print('This is the user id number', user_id)

#         # Check if the user is already subscribed to this newspaper
#         existing_subscription = Subscription.query.filter_by(user_id=user_id, newspaper_id=newspaper_id, active=True).first()
#         print('this is existing subscription', existing_subscription)
#         if existing_subscription:
#             flash('You are already subscribed to this newspaper.', 'info')
#         else:
#             # Create a new subscription
#             new_subscription = Subscription(
#                 user_id=user_id,
#                 newspaper_id=newspaper_id,
#                 active=True)
#             print('this is new subscription', new_subscription)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')
#             print(new_subscription)

#         return redirect(url_for('main.view_latest_issues'))

#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers)


# @main.route('/subscribe', methods=['GET', 'POST'])
# # @login_required  # Protect the route to ensure only authenticated users can access
# def subscribe():
#     # Redirect users who are not logged in to the login page
#     if 'logged_in' not in session or not session['logged_in']:
#         flash('You need to be logged in to subscribe.', 'info')
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         # Assume 'newspaper' is the name attribute in your select dropdown
#         newspaper_id = request.form.get('newspaper')
#         user_id = session.get('user_id')  # Use Flask-Login to get the current user's id

#         # Check if the user is already subscribed to this newspaper
#         existing_subscription = Subscription.query.filter_by(user_id=user_id, newspaper_id=newspaper_id, active=True).first()
#         if existing_subscription:
#             flash('You are already subscribed to this newspaper.', 'info')
#         else:
#             # Create a new subscription
#             new_subscription = Subscription(user_id=user_id, newspaper_id=newspaper_id, active=True)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')

#         return redirect(url_for('main.view_latest_issues'))

#     # Fetch all newspapers to populate the dropdown in the subscription form
#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers)



# @main.route('/subscribe', methods=['GET', 'POST'])
# # @login_required
# def subscribe():
#     if request.method == 'POST':
#         try:
#             newspaper_id = request.form.get('newspaper.newspaper.id')
#             if not newspaper_id:
#                 raise ValueError('Invalid newspaper selection.')
#             print('this is the newspaper id', newspaper_id)

#             # Check for existing subscription (optional, modify if needed)
#             existing_subscription = Subscription.query.filter_by(user_id=current_user.id, newspaper_id=newspaper_id).first()
#             if existing_subscription and existing_subscription.active:
#                 flash('You are already subscribed to this edition.', 'info')
#                 return redirect(url_for('main.view_latest_issues'))

#             # Create new subscription
#             new_subscription = Subscription(user_id=current_user.id, newspaper_id=newspaper_id, active=True)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')
#             return redirect(url_for('main.view_latest_issues'))
#         except (ValueError, IntegrityError) as e:
#             db.session.rollback()  # Rollback on errors
#             flash(f'Subscription failed: {str(e)}', 'danger')
#             return redirect(url_for('main.subscribe'))  # Redirect back to subscribe page

#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers)


# @main.route('/subscribe', methods=['GET', 'POST'])
# # @login_required  # Ensure this route is only accessible to authenticated users
# def subscribe():
#     if request.method == 'POST':
#         try:
#             # Corrected to fetch 'newspaper_id' from the form
#             newspaper_id = request.form.get('newspaper_id')
#             if not newspaper_id:
#                 raise ValueError('Invalid newspaper selection.')
#             print('this is the newspaper id', newspaper_id)

#             # Check for existing subscription (optional, modify if needed)
#             existing_subscription = Subscription.query.filter_by(user_id=current_user.id, newspaper_id=newspaper_id).first()
#             if existing_subscription and existing_subscription.active:
#                 flash('You are already subscribed to this newspaper.', 'info')
#                 return redirect(url_for('main.view_latest_issues'))

#             # Create new subscription
#             new_subscription = Subscription(user_id=current_user.id, newspaper_id=newspaper_id, active=True)
#             db.session.add(new_subscription)
#             db.session.commit()
#             flash('Subscription successful!', 'success')
#             return redirect(url_for('main.view_latest_issues'))
#         except (ValueError, IntegrityError) as e:
#             db.session.rollback()  # Rollback on errors
#             flash(f'Subscription failed: {str(e)}', 'danger')
#             return redirect(url_for('main.subscribe'))  # Redirect back to subscribe page

#     newspapers = Newspaper.query.all()
#     return render_template('subscription.html', newspapers=newspapers, user=current_user)


@main.route('/subscribe', methods=['GET', 'POST'])
# @login_required  # Ensure this route is only accessible to authenticated users
def subscribe():
    newspapers = Newspaper.query.all()
    return render_template('subscription.html', newspapers=newspapers, user=current_user)



# @main.route('/manage_subscriptions')
# # @login_required
# def manage_subscriptions():
#     subscriptions = Subscription.query.filter_by(user_id=user.id).all()
#     return render_template('manage_subscriptions.html', subscriptions=subscriptions)

@main.route('/manage_subscriptions')
# @login_required  # Uncomment this if using Flask-Login
def manage_subscriptions():
    # Ensure there is a logged-in user
    user_id = session.get('user_id')
    if not user_id:
        # Redirect to login page if not logged in
        return redirect(url_for('main.login'))

    subscriptions = Subscription.query.filter_by(user_id=user_id).all()
    return render_template('manage_subscription.html', subscriptions=subscriptions)



# @main.route('/view_latest_issues')
# @cross_origin()
# @require_subscription
# def view_latest_issues():
#     newspapers = Newspaper.query.order_by(Newspaper.publication_date.desc()).all()
#     return render_template('view_latest_issue.html', newspapers=newspapers)

@main.route('/view_latest_issues')
@cross_origin()
# @require_subscription
def view_latest_issues():
    try:
        newspapers = Newspaper.query.order_by(Newspaper.publication_date.desc()).all()
    except SQLAlchemyError as e:
        # Log the error for debugging purposes
        main.logger.error(f"Database error occurred: {str(e)}")
        # Flash a user-friendly message
        flash('An error occurred while fetching the latest issues. Please try again later.', 'error')
        # Redirect to the homepage or another appropriate page
        return redirect(url_for('main.index'))

    # Proceed if there are no errors
    return render_template('view_latest_issue.html', newspapers=newspapers)

@main.route('/read_newspaper/<int:id>')
@cross_origin()
# @require_subscription
# @requires_subscription_to_newspaper
def read_newspaper(id):
    newspaper = Newspaper.query.get_or_404(id)
    pdf_path = 'static/pdfs'
    return send_from_directory(directory=pdf_path, path=newspaper.pdf_file, as_attachment=False)



@main.route('/view_newspaper/<int:newspaper_id>')
# @require_subscription
@requires_subscription_to_newspaper
@cross_origin(origins='http://localhost:5000', supports_credentials=True)
def view_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    pdf_url = url_for('static', filename='pdfs/' + newspaper.pdf_file)
    return render_template('view_pdf.html', pdf_url=pdf_url)


@main.route('/delete_newspaper/<int:newspaper_id>', methods=['POST'])
def delete_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    db.session.delete(newspaper)
    db.session.commit()
    flash('Newspaper deleted successfully.', 'success')
    return redirect(url_for('main.view_latest_issues'))



@main.route('/subscribe_and_pay/<int:newspaper_id>')
# @login_required
def subscribe_and_pay(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    # Display payment form and pass the newspaper as context
    return render_template('payment.html', newspaper=newspaper)



# @main.route('/process_payment', methods=['GET', 'POST'])
# # @login_required
# def process_payment():
#     # newspaper_id = request.form.get('newspaper_id')
#     # if newspaper_id:
#     #     newspaper = Newspaper.query.get(newspaper_id)
#     #     if newspaper:
#     #         print('This is the title', newspaper.title)
#     #         # Proceed with your logic here
#     #     else:
#     #         return "Invalid newspaper selected", 404
#     # print('this is the newspaper id', newspaper_id)
#     subscription_id = request.form.get('subscription_id')  # If passed in a POST request

#     # Fetch the subscription using the ID
#     subscription = Subscription.query.get_or_404(subscription_id)
    
#     # Now you can access the amount
#     amount = subscription.amount
#     print('The amount is:', amount)

#     subscription = Subscription.query.get_or_404(amount)

#     amount = subscription['amount']
#     email = current_user.email

#     response = Transaction.initialize(amount=str(amount), email=email)

#     print(f"{amount} {email}")
 
    

#     a_url = response['data']['authorization_url']
#     return redirect(a_url)


@main.route('/process_payment', methods=['GET', 'POST'])
# @login_required
def process_payment():
    # subscription = Subscription.query.all()
    amount = '1000'
    email = current_user.username
    print(subscription)

    response = Transaction.initialize(amount=str(amount))

    print(f"{amount}")
    subscription = Subscription.query.all()
    create_subscription_instance = Subscription(
        user_id=current_user.id,  # Assuming the user is logged in and you're using Flask-Login
        amount=amount,
        newspaper_id=newspaper_id,
        active=True,  # Set to True if the subscription should be active immediately upon creation
        subscription_date=datetime.utcnow(),
        payment_id=response.get('data', {}).get('reference')  # Extracting payment ID/reference from the response
    )

    db.session.add(create_subscription_instance)
    db.session.commit()



    a_url = response['data']['authorization_url']
    return redirect(a_url)



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
            subscription.paid = True
            db.session.commit()
            return redirect(url_for('core.dashboard'))

        # print(f"No subscription or tutor fee payment found for ID: {paramz}")
        
    else:
        # If the status is not 'success', consider logging the status for debugging
        print(f"Payment verification failed with status: {status}")
    
    # Return a failure response if the status is not 'success' or if no matching record is found
    return jsonify({'message': 'Payment verification failed'}), 400

