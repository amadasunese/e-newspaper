from flask import Flask
from src.accounts.models import db, User
from views import main
from config import Config
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_cors import CORS
from flask_mail import Mail

mail = Mail()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    mail.init_app(app)
    cors = CORS(app)
    cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
    db.init_app(app)



    migrate = Migrate(app, db)


    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'main.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    app.register_blueprint(main)

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
