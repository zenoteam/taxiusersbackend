from taxiusers_backend.app import create_app
from taxiusers_backend.models import UserModel
from datetime import datetime

if __name__ == '__main__':
    application = create_app()
    application.app_context().push()

    # Create some test data
    test_data = [
        # super admin user
        ('bruce', "bruce", 1, datetime.now(), "dnd"),
        # admin user
        ('esther', "esther", 2, datetime.now(), "hdhd"),
        # driver
        ('stephen', "stephen", 3, datetime.now(), "ddd"),
        # rider
        ('jacob', "jacob", 4, datetime.now(), "dddd"),
    ]
    for username, password, role, createdAt, firebaseToken in test_data:
        user = UserModel(username=username,
                         password=password,
                         role=role,
                         createdAt=createdAt,
                         firebaseToken=firebaseToken)
        application.db.session.add(user)

    application.db.session.commit()
