from flask import Flask
from flask_restplus import Api
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS

migrate = Migrate()


def create_app():
    from .namespaces.api import api_namespace
    from .namespaces.admin import admin_namespace

    application = Flask(__name__)
    api = Api(application,
              version='0.1',
              title='Taxi Authentication Service',
              description='Taxi Users Authentication Backend API')

    from taxiusers_backend.db import db, db_config
    application.config['RESTPLUS_MASK_SWAGGER'] = False
    CORS(application)
    application.config.update(db_config)
    db.init_app(application)
    application.db = db

    from taxiusers_backend.models import bcrypt
    bcrypt.init_app(application)

    migrate.init_app(application, db=db)
    application.cli.add_command(MigrateCommand, name="db")
    api.add_namespace(api_namespace)
    api.add_namespace(admin_namespace)

    return application
