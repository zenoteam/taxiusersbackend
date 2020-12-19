from taxiusers_backend.app import create_app
from taxiusers_backend.models import UserModel
from datetime import datetime

if __name__ == '__main__':
    application = create_app()
    application.app_context().push()

    # Create some test data
    test_data = [
        # super admin user
        ('bruce', "bruce", 1, datetime.now()),
        # admin user
        ('esther', "esther", 2, datetime.now()),
        # driver
        ('stephen', "stephen", 3, datetime.now()),
        # rider
        ('jacob', "jacob", 4, datetime.now()),
    ]
    for username, password, role, createdAt in test_data:
        user = UserModel(
            username=username,
            password=password,
            role=role,
            createdAt=createdAt
        )
        application.db.session.add(user)

    application.db.session.commit()
