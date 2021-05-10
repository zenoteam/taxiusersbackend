from uuid import uuid4

from sqlalchemy import func
from taxiusers_backend.db import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()


class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auth_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True)
    phone_number = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(250))
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

    # superadmin: 1, admin: 2, drivers: 3, riders/passengers: 4
    role = db.Column(db.Integer, nullable=False, default=4)

    firebase_token = db.Column(db.String(250))

    def __init__(self, email, password, phone_number, role, created_at,
                 firebase_token):
        self.email = email
        self.phone_number = phone_number
        self.auth_id = str(uuid4())
        # Hash and Salt Password
        self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
        self.role = role
        self.created_at = created_at
        self.firebase_token = firebase_token
