from functools import wraps

from flask import flash, redirect, url_for, session
from flask_login import current_user
from src.accounts.models import Subscription, Newspaper
from datetime import datetime


def logout_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            flash("You are already authenticated.", "info")
            return redirect(url_for("core.newspapers"))
        return func(*args, **kwargs)

    return decorated_function

def check_is_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.is_confirmed is False:
            flash("Please confirm your account!", "warning")
            return redirect(url_for("main.inactive"))
        return func(*args, **kwargs)

    return decorated_function


def check_is_subscribed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.subscription or current_user.subscription.end_date < datetime.utcnow():
            flash("Please subscribe to use this service", "warning")
            return redirect(url_for("core.subscribe"))
        return func(*args, **kwargs)

    return decorated_function


def is_parent(user_id):
    # This function checks if a parent with the given user_id exists
    return Parent.query.filter_by(user_id=user_id).first() is not None

def check_is_registered(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not is_parent(current_user.id):
            flash('You need to be registered as a parent to use this service.', 'warning')
            return redirect(url_for('core.register_parent'))
        return func(*args, **kwargs)
    return decorated_function

def is_tutor(user_id):
    # This function checks if a tutor with the given user_id exists
    return Tutor.query.filter_by(user_id=user_id).first() is not None

# def check_is_tutor_registered(func):
#     @wraps(func)
#     def decorated_function(*args, **kwargs):
#         if not is_tutor(current_user.id):
#             flash('You need to be registered as a tutor to use this service.', 'warning')
#             return redirect(url_for('core.tutor_registration'))
#         return func(*args, **kwargs)
#     return decorated_function


# def is_tutor(user_id):
#     # Assuming you have a function to check if the user is a tutor
#     # This is just a placeholder. Implement according to your application logic
#     tutor = Tutor.query.filter_by(user_id=user_id).first()
#     return tutor is not None

def has_paid_fee(tutor_id):
    # Query the database to check if the fee_paid field for the tutor is True
    tutorfeepayment = TutorFeePayment.query.filter_by(tutor_id=tutor_id).first()
    return tutorfeepayment and tutorfeepayment.paid

def check_is_tutor_registered(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # print(f"Checking tutor status for user {current_user.id}")
        if not is_tutor(current_user.id):
            flash('You need to be registered as a tutor to use this service.', 'warning')
            return redirect(url_for('core.tutor_registration'))
        elif not has_paid_fee(current_user.id):
            flash('You need to pay the registration fee to use this service.', 'warning')
            return redirect(url_for('core.pay_fee'))
        return func(*args, **kwargs)
    return decorated_function


#################

def require_subscription(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is logged in and has an active subscription
        # if not current_user.is_authenticated:
        #     flash("You must be logged in to access this page.", "warning")
        #     return redirect(url_for('main.login'))
        
        user_subscriptions = Subscription.query.filter_by(user_id=current_user.id, active=True).first()
        if not user_subscriptions:
            flash("You need an active subscription to access this page.", "warning")
            return redirect(url_for('main.index'))  # or any other page
        
        return f(*args, **kwargs)
    return decorated_function

# def require_subscription(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         # Ensure the user is logged in
#         if 'logged_in' not in session or not session['logged_in']:
#             flash("You must be logged in to access this page.", "warning")
#             return redirect(url_for('main.login'))
        
#         # Check if the logged-in user has at least one active subscription
#         user_subscriptions = Subscription.query.filter_by(user_id=current_user.get_id(), active=True).first()
#         if not user_subscriptions:
#             flash("You need an active subscription to access this page.", "warning")
#             return redirect(url_for('main.subscribe'))
        
#         return f(*args, **kwargs)
#     return decorated_function


def requires_subscription_to_newspaper(f):
    @wraps(f)
    def decorated_function(newspaper_id, *args, **kwargs):
        # Check if the user is logged in
        # if 'logged_in' not in session or not session['logged_in']:
        #     flash("You must be logged in to access this page.", "warning")
        #     return redirect(url_for('main.login'))
        
        # Fetch the user_id from the session
        user_id = session.get('user_id')

        # Check if there's an active subscription for the newspaper
        subscription = Subscription.query.filter_by(user_id=user_id, newspaper_id=newspaper_id, active=True).first()
        if not subscription:
            flash("You do not have access to this newspaper.", "warning")
            return redirect(url_for('main.subscribe'))  # or another appropriate page
        
        # Proceed with the original function if the subscription check passes
        return f(newspaper_id, *args, **kwargs)
    return decorated_function