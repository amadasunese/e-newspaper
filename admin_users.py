from flask import Flask, render_template, request, redirect, url_for, flash
from app import create_app
from src.accounts.models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

def add_admin(username, password):
    with app.app_context():
        # Check for existing user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print("An account with this email already exists.")
            return
        
        if isinstance(password, bytes):
            password = password.decode('utf-8')

        # Hash the password
        hashed_password = generate_password_hash(password)
        
        admin_user = User(username=username, password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin {username} {password} added successfully.")

if __name__ == '__main__':
    username = input("Enter admin email: ")
    # last_name = input("Enter admin last name: ")
    # email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    add_admin(username, password)
