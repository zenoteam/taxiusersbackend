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
    'email': fields.String(),
    'phone_number': fields.String(),
    'role': fields.Integer(),
    # DO NOT RETURN THE PASSWORD!!!
    'last_login_at': fields.DateTime(),
    'created_at': fields.DateTime(),
    'firebase_token': fields.String()
}
user_model = admin_namespace.model('User', model)

user_parser = admin_namespace.parser()
user_parser.add_argument('email', type=str, required=True, help='email')
user_parser.add_argument('phone_number',
                         type=str,
                         required=True,
                         help='phone_number')
user_parser.add_argument('password', type=str, required=True, help='Password')
user_parser.add_argument('firebase_token',
                         type=str,
                         required=False,
                         help='firebase_token')
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
        user = (UserModel.query.filter(
            UserModel.phone_number == args['phone_number']).first())
        if user:
            result = {
                "result": "error",
                "status_code": 422,
                'message': 'phone number already exists, try another one'
            }
            return result, http.client.OK

        user = (UserModel.query.filter(
            UserModel.email == args['email']).first())
        if user:
            result = {
                "result": "error",
                "status_code": 422,
                'message': 'email already exists, try another one'
            }
            return result, http.client.OK

        new_user = UserModel(email=args['email'],
                             phone_number=args["phone_number"],
                             password=args['password'],
                             role=args['role'],
                             created_at=datetime.utcnow(),
                             firebase_token=args['firebase_token'])
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            result = {
                "result": "error",
                "status_code": 422,
                'message':
                'email or phone number already exists, try another one'
            }
            return result, http.client.OK

        result = admin_namespace.marshal(new_user, user_model)

        return result, http.client.CREATED


@admin_namespace.route('/users/<int:user_id>/')
class UserDelete(Resource):
    @admin_namespace.expect(authParser)
    @admin_namespace.doc('delete_user')
    def delete(self, user_id: int):
        """
        Delete a user
        """
        args = authParser.parse_args()
        authentication_header_parser(args['Authorization'])

        user = UserModel.query.get(user_id)
        if not user:
            # The user is not present
            return '', http.client.NO_CONTENT

        if user.role == 1:
            return 'Unable to delete super user', http.client.FORBIDDEN

        db.session.delete(user)
        db.session.commit()

        return '', http.client.NO_CONTENT


@admin_namespace.route('/users/checkemail/<string:email>')
class CheckUser(Resource):
    def get(self, email: str):
        """
        Checks if a email exists
        """
        args = authParser.parse_args()

        user = UserModel.query.filter(UserModel.email == email).first()

        if not user:
            # The email doesnt exist
            return {"result": False}, http.client.OK
        user = admin_namespace.marshal(user, user_model)
        return {
            "result": "success",
            "status_code": 200,
            "result": user
        }, http.client.OK


@admin_namespace.route('/users/checkphonenum/<string:phone_number>')
class CheckUser(Resource):
    def get(self, phone_number: str):
        """
        Checks if a phone number exists
        """
        args = authParser.parse_args()

        user = UserModel.query.filter(
            UserModel.phone_number == phone_number).first()

        if not user:
            # The email doesnt exist
            return {"result": False}, http.client.OK
        user = admin_namespace.marshal(user, user_model)
        return {
            "result": "success",
            "status_code": 200,
            "result": user
        }, http.client.OK
