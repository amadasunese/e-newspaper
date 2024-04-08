from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String, nullable=True)
#     username= db.Column(db.String(80), unique=True, nullable=True)
#     password = db.Column(db.String(120), nullable=False)
#     is_admin = db.Column(db.Boolean, default=False)
#     subscriptions = db.relationship('Subscription', backref='user', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=True)
    username= db.Column(db.String(80), unique=True, nullable=False)  # Ensure email is not nullable
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(80))  # Add the email column
    is_confirmed = db.Column(db.Boolean, nullable=True, default=False)
    subscriptions = db.relationship('Subscription', backref='user', lazy=True)

class Newspaper(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=True)
    pdf_file = db.Column(db.String(300), nullable=False)
    publication_date = db.Column(db.DateTime, default=datetime.utcnow)
    thumbnail = db.Column(db.String(300))  # Path to the thumbnail image
    subscriptions = db.relationship('Subscription', backref='newspaper', lazy=True)


class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer)
    newspaper_id = db.Column(db.Integer, db.ForeignKey('newspaper.id'), nullable=False)
    active = db.Column(db.Boolean, default=True)
    # renewal_date = db.Column(db.Date, nullable=True)
    subscription_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_id = db.Column(db.String(50), nullable=False)


