from taxiusers_backend.app import create_app
from taxiusers_backend.models import UserModel
from datetime import datetime

if __name__ == '__main__':
    application = create_app()
    application.app_context().push()

    # Create some test data
    test_data = [
        # username, timestamp, text
        ('bruce', "bruce", datetime.now()),
        ('stephen', "stephen", datetime.now()),
    ]
    for username, password, creation in test_data:
        user = UserModel(username=username,
                         password=password,
                         creation=creation)
        application.db.session.add(user)

    application.db.session.commit()
