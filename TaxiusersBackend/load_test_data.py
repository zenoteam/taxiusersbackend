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
        # normal user
        ('stephen', "stephen", 0, datetime.now()),
    ]
    for username, password, admin, creation in test_data:
        user = UserModel(
            username=username,
            password=password,
            admin=admin,
            creation=creation
        )
        application.db.session.add(user)

    application.db.session.commit()
