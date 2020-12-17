from sqlalchemy import func
from taxiusers_backend.db import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()


class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(250))
    admin = db.Column(db.Integer, nullable=False, default=0)  # normal users: 0, super admin users: 1, admin users: 2
    creation = db.Column(db.DateTime, server_default=func.now())

    def __init__(self, username, password, admin, creation):
        self.username = username
        # Hash and Salt Password
        self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
        self.admin = admin
        self.creation = creation
