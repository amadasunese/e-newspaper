import os
from flask_migrate import Migrate
# from app import app, db

class Config:
    SECRET_KEY = '17287727877878'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///newspaper.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/pdfs'

   

# location ~* \.pdf$ {
#     add_header 'Access-Control-Allow-Origin' '*';
# }
    # migrate = Migrate(app, db)
# CORS(app, resources={
#     r"/api/*": {
#         "origins": ["http://localhost:3000", "https://example.com"],
#         "methods": ["GET", "POST"],
#         "allow_headers": ["Content-Type", "Authorization"]
#     }
# })