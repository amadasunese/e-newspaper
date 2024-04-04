from flask import current_app, Blueprint, send_from_directory, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from src.accounts.models import db, User, Newspaper, Subscription, Edition
from werkzeug.utils import secure_filename
import os
from flask_login import login_required, current_user
from config import Config
import fitz  # PyMuPDF
from datetime import datetime
from flask_cors import CORS
from app import app



cors = CORS(app)
core_bp = Blueprint("core", __name__)


@core.route('/admin')
def admin():
    # Admin view logic here
    users = User.query.all()
    return render_template('admin.html', users=users)


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


@main.route('/subscribe', methods=['GET', 'POST'])
@login_required
def subscribe():
    if request.method == 'POST':
        edition_id = request.form.get('edition')
        # Check if the user is already subscribed to this edition
        existing_subscription = Subscription.query.filter_by(user_id=current_user.id, edition_id=edition_id).first()
        if existing_subscription:
            flash('You are already subscribed to this edition.', 'info')
        else:
            new_subscription = Subscription(user_id=current_user.id, edition_id=edition_id, active=True)
            db.session.add(new_subscription)
            db.session.commit()
            flash('Subscription successful!', 'success')
        return redirect(url_for('main.view_latest_issues'))
    
    editions = Edition.query.all()
    return render_template('subscription.html', editions=editions)


@main.route('/manage_subscriptions')
@login_required
def manage_subscriptions():
    subscriptions = Subscription.query.filter_by(user_id=current_user.id).all()
    return render_template('manage_subscriptions.html', subscriptions=subscriptions)


@main.route('/view_latest_issues')
def view_latest_issues():
    newspapers = Newspaper.query.order_by(Newspaper.publication_date.desc()).all()
    return render_template('view_latest_issue.html', newspapers=newspapers)


@main.route('/read_newspaper/<int:id>')
def read_newspaper(id):
    newspaper = Newspaper.query.get_or_404(id)
    pdf_path = 'static/pdfs'  # Adjust this path to where you store your PDF files
    return send_from_directory(directory=pdf_path, path=newspaper.pdf_file, as_attachment=False)



@main.route('/view_newspaper/<int:newspaper_id>')
def view_newspaper(newspaper_id):
    newspaper = Newspaper.query.get_or_404(newspaper_id)
    pdf_url = url_for('static', filename='pdfs/' + newspaper.pdf_file)
    return render_template('view_pdf.html', pdf_url=pdf_url)
