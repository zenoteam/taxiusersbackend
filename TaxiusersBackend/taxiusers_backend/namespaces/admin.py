import http.client
from flask_restplus import Namespace, Resource, fields
from datetime import datetime
from taxiusers_backend.models import UserModel
from taxiusers_backend.db import db
from sqlalchemy.exc import IntegrityError

from taxiusers_backend.namespaces.api import authentication_header_parser

admin_namespace = Namespace('admin', description='Admin operations')

model = {
    'id': fields.Integer(),
    'auth_id': fields.String(),
    'username': fields.String(),
    'role': fields.Integer(),
    # DO NOT RETURN THE PASSWORD!!!
    'lastLoginAt': fields.DateTime(),
    'createdAt': fields.DateTime(),
}
user_model = admin_namespace.model('User', model)

user_parser = admin_namespace.parser()
user_parser.add_argument('username', type=str, required=True, help='Username')
user_parser.add_argument('password', type=str, required=True, help='Password')
user_parser.add_argument(
    'role',
    type=int,
    choices=(0, 1, 2),
    required=False,
    help='The role of the user (1: superadmin, 2: admin, 3: drivers, 4: riders)'
)

authParser = admin_namespace.parser()
authParser.add_argument('Authorization',
                        location='headers',
                        type=str,
                        help='Bearer Access Token')


@admin_namespace.route('/users/')
class UserCreate(Resource):
    @admin_namespace.expect(user_parser)
    @admin_namespace.marshal_with(user_model, code=http.client.CREATED)
    def post(self):
        """
        Create a new user
        """
        args = user_parser.parse_args()
        # password = args['password']
        """# Hash and Salt Password
        password_hash = bcrypt.generate_password_hash(password)\
            .decode('UTF-8')"""

        new_user = UserModel(username=args['username'],
                             password=args['password'],
                             role=args['role'],
                             createdAt=datetime.utcnow())
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            result = {'result': 'Username already exists, try another one'}
            return result, http.client.UNPROCESSABLE_ENTITY

        result = admin_namespace.marshal(new_user, user_model)

        return result, http.client.CREATED


@admin_namespace.route('/users/<int:userId>/')
class UserDelete(Resource):
    @admin_namespace.expect(authParser)
    @admin_namespace.doc('delete_user')
    def delete(self, userId: int):
        """
        Delete a user
        """
        args = authParser.parse_args()
        authentication_header_parser(args['Authorization'])

        user = UserModel.query.get(userId)
        if not user:
            # The user is not present
            return '', http.client.NO_CONTENT

        if user.role == 1:
            return 'Unable to delete super user', http.client.FORBIDDEN

        db.session.delete(user)
        db.session.commit()

        return '', http.client.NO_CONTENT
