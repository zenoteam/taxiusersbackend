from sqlalchemy import func
from taxiusers_backend.db import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()


class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    # DO NOT EVER STORE PLAIN PASSWORDS IN DATABASES
    # THIS IS AN EXAMPLE!!!!!
    password = db.Column(db.String(250))
    creation = db.Column(db.DateTime, server_default=func.now())

    def __init__(self, username, password, creation):
        self.username = username
        # Hash and Salt Password
        self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
        self.creation = creation
