import http.client
from datetime import datetime

import validators
from flask_restplus import Namespace, Resource, fields
from sqlalchemy.exc import IntegrityError

from taxiusers_backend.namespaces.api import authentication_header_parser
from taxiusers_backend.models import UserModel
from taxiusers_backend.db import db

admin_namespace = Namespace(name="Admin V1.1",
                            description='Admin operations',
                            path="/admin/v1.1")

prefix_list = ["080", "090", "070", "081", "071", "091"]

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
    def post(self):
        """
        Create a new user
        """
        args = user_parser.parse_args()

        phone_number = args["phone_number"]

        first_three = phone_number[:3]

        if first_three not in prefix_list and first_three != "+23":
            response = {
                "status": "error",
                "details": {
                    "message": "Pass in a valid phone-number"
                }
            }
            return response, http.client.BAD_REQUEST

        if not (len(phone_number) == 11 or len(phone_number) == 14):

            response = {
                "status": "error",
                "details": {
                    "message": "The lenth of number passed is invalid"
                }
            }
            return response, http.client.BAD_REQUEST

        user = (UserModel.query.filter(
            UserModel.phone_number == phone_number).first())

        if user:
            result = {
                "status": "error",
                "result": {
                    'message': 'Phone Number already exists, try another one.'
                }
            }
            return result, http.client.CONFLICT

        if not validators.email(args["email"]):
            response = {
                "status": "error",
                "details": {
                    "message": "Input a valid email address"
                }
            }
            return response, http.client.BAD_REQUEST

        user = (UserModel.query.filter(
            UserModel.email == args['email']).first())
        if user:
            result = {
                "status": "error",
                "result": {
                    'message': 'Email already exists, try another one.'
                }
            }
            return result, http.client.CONFLICT

        email = args['email'].lower()
        new_user = UserModel(email=email,
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
                "status": "error",
                "result": {
                    'message':
                    'Email or Phone Number already exists, try another one.'
                }
            }
            return result, http.client.CONFLICT

        result = admin_namespace.marshal(new_user, user_model)

        response = {"status": "success", "result": result}

        return response, http.client.CREATED


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


@admin_namespace.route('/users/email/<string:email>')
class CheckUser(Resource):
    def get(self, email: str):
        """
        Checks if a email exists
        """
        args = authParser.parse_args()

        if not validators.email(email):
            response = {
                "status": "error",
                "details": {
                    "message": "Input a valid email address"
                }
            }
            return response, http.client.BAD_REQUEST

        user = UserModel.query.filter(UserModel.email == email).first()

        if not user:
            # The email doesnt exist
            return {
                "status": "error",
                "details": {
                    "message": "Not Found"
                }
            }, http.client.NOT_FOUND
        user = admin_namespace.marshal(user, user_model)
        return {
            "status": "success",
            "details": {
                "result": user
            }
        }, http.client.OK


@admin_namespace.route('/users/phone-number/<string:phone_number>')
class CheckUser(Resource):
    def get(self, phone_number: str):
        """
        Checks if a phone number exists
        """
        args = authParser.parse_args()

        first_three = phone_number[:3]

        if first_three not in prefix_list and first_three != "+23":
            response = {
                "status": "error",
                "details": {
                    "message": "Input in a valid phone-number"
                }
            }
            return response, http.client.BAD_REQUEST

        if len(phone_number) == 11 or len(phone_number) == 14:
            user = (UserModel.query.filter(
                UserModel.phone_number == phone_number).first())

            if not user:
                response = {
                    "status": "error",
                    "detials": {
                        "message": "User with phone number doesnt exist"
                    }
                }
                return response, http.client.NOT_FOUND

        user = UserModel.query.filter(
            UserModel.phone_number == phone_number).first()

        if not user:
            # The email doesnt exist
            return {
                "status": "error",
                "details": {
                    "message": "Not Found"
                }
            }, http.client.OK
        user = admin_namespace.marshal(user, user_model)
        return {
            "status": "success",
            "details": {
                "result": user
            }
        }, http.client.OK
