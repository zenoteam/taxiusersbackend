import http.client
from datetime import datetime, timedelta

from flask import abort
from flask_restplus import Namespace, Resource
from sqlalchemy import func

from taxiusers_backend import config
from taxiusers_backend.db import db
from taxiusers_backend.models import UserModel, bcrypt
from taxiusers_backend.token import generate_token_header, validate_token_header, blacklist_token

api_namespace = Namespace('api', description='API operations')


def authentication_header_parser(value):
    """
    Validates and returns decoded token payload
    """
    payload = validate_token_header(value, config.PUBLIC_KEY)
    if payload is None:
        abort(401)
    return payload


# Input and output formats for Users
authentication_parser = api_namespace.parser()
authentication_parser.add_argument('Authorization',
                                   location='headers',
                                   type=str,
                                   help='Bearer Access Token')

login_parser = api_namespace.parser()
login_parser.add_argument('username', type=str, required=True, help='username')
login_parser.add_argument('password', type=str, required=True, help='password')


@api_namespace.route('/login/')
class UserLogin(Resource):
    @api_namespace.doc('login')
    @api_namespace.expect(login_parser)
    def post(self):
        """
        Login and return a valid Authorization header
        """
        args = login_parser.parse_args()

        # Search for the user
        user = (UserModel.query.filter(
            UserModel.username == args['username']).first())
        if not user:
            return '', http.client.UNAUTHORIZED

        # Check the password
        # REMEMBER, THIS IS NOT SAFE. DO NOT STORE PASSWORDS IN PLAIN
        auth_user = bcrypt.check_password_hash(user.password, args['password'])

        if not auth_user:
            return '', http.client.UNAUTHORIZED

        # Generate the header
        tokenPayload = {'id': user.id}
        if user.role == 1 or user.role == 2:
            tokenPayload['admin'] = user.role
        header = generate_token_header(tokenPayload, config.PRIVATE_KEY)

        isFirstLogin = True if user.lastLoginAt is None else False

        # update last login timestamp
        user.lastLoginAt = datetime.utcnow()

        # save update
        db.session.add(user)
        db.session.commit()

        response = {'Authorized': header}
        if isFirstLogin:
            response['firstLogin'] = 'true'
        response["auth_id"] = user.auth_id

        return response, http.client.OK


@api_namespace.route('/verify/')
class UserVerify(Resource):
    @api_namespace.doc('verify')
    @api_namespace.expect(authentication_parser)
    def get(self):
        """
        Verifies user token
        """
        args = authentication_parser.parse_args()

        # get payload from bearer token
        payload = authentication_header_parser(args['Authorization'])

        if not payload:
            return '', http.client.UNAUTHORIZED

        return payload


@api_namespace.route('/logout/')
class UserLogout(Resource):
    @api_namespace.doc('logout')
    @api_namespace.expect(authentication_parser)
    def post(self):
        """
        Blacklists a user token
        """
        args = authentication_parser.parse_args()
        payload = authentication_header_parser(args['Authorization'])

        if blacklist_token(payload):
            return http.client.NO_CONTENT
        return http.client.INTERNAL_SERVER_ERROR


change_pw_parser = authentication_parser.copy()
change_pw_parser.add_argument('old_password',
                              type=str,
                              required=True,
                              help='old password')
change_pw_parser.add_argument('new_password',
                              type=str,
                              required=True,
                              help='new password')


@api_namespace.route('/password/change/')
class ChangePwd(Resource):
    @api_namespace.doc('change_password')
    @api_namespace.expect(change_pw_parser)
    def post(self):
        """
        Change a user password
        """
        args = change_pw_parser.parse_args()
        userId = authentication_header_parser(args['Authorization'])['id']
        old_password = args['old_password']

        # Get user
        user = (UserModel.query.filter(UserModel.id == userId).one())

        auth_user = bcrypt.check_password_hash(user.password, old_password)

        if not auth_user:
            return '', http.client.UNAUTHORIZED

        user.password = bcrypt.generate_password_hash(
            args['new_password']).decode('UTF-8')

        db.session.add(user)
        db.session.commit()

        return http.client.OK


update_pw_parser = authentication_parser.copy()
update_pw_parser.add_argument('userId',
                              type=int,
                              required=True,
                              help='The user Id')
update_pw_parser.add_argument('new_password',
                              type=str,
                              required=True,
                              help='The new password')


@api_namespace.route('/password/update/')
class UpdatePwd(Resource):
    @api_namespace.doc('update_password')
    @api_namespace.expect(update_pw_parser)
    def post(self):
        """
        Update a user's password, endpoint only accessible by (super) admin
        """
        args = update_pw_parser.parse_args()
        payload = authentication_header_parser(args['Authorization'])

        # check that user is an admin
        if 'admin' not in payload:
            abort(403)

        # Get user
        user = (UserModel.query.filter(UserModel.id == args['userId']).one())

        # check if password to be updated belongs to (super) admin
        if user.role == 1 or user.role == 2:
            if 'admin' in payload:
                if payload['admin'] != 1:
                    abort(403)

        user.password = bcrypt.generate_password_hash(
            args['new_password']).decode('UTF-8')

        db.session.add(user)
        db.session.commit()

        return http.client.OK


dateQuery_parser = authentication_parser.copy()
dateQuery_parser.add_argument("startdate",
                              type=str,
                              required=True,
                              help="The start date format '%d/%m/%Y'")
dateQuery_parser.add_argument('enddate',
                              type=str,
                              required=True,
                              help="The end date format '%d/%m/%Y'")


@api_namespace.route('/stat/datequery/')
class UsersDateQuery(Resource):
    @api_namespace.doc('query count in db: daily')
    @api_namespace.expect(dateQuery_parser)
    def get(self):
        """
        Help find  the daily signup within a range of dates
        """
        args = dateQuery_parser.parse_args()
        authentication_header_parser(args['Authorization'])

        start_date_str = args['startdate']
        end_date_str = args['enddate']

        start_date = datetime.strptime(start_date_str, "%d/%m/%Y").date()

        end_date = datetime.strptime(end_date_str, "%d/%m/%Y").date()

        result = {}

        if start_date > end_date:
            return '', http.client.BAD_REQUEST

        while start_date <= end_date:
            user = (db.session.query(func.count(UserModel.id)).filter(
                func.date(UserModel.createdAt) == start_date).all())
            date = start_date.strftime("%d/%m/%Y")
            result[date] = user[0][0]

            start_date = start_date + timedelta(days=1)

        return result


monthQuery_parser = authentication_parser.copy()
monthQuery_parser.add_argument('year',
                               type=str,
                               required=True,
                               help='The year')


@api_namespace.route('/stat/monthquery/')
class UsersMonthQuery(Resource):
    @api_namespace.doc('query count in db: monthly')
    @api_namespace.expect(monthQuery_parser)
    def get(self):
        """
        Help find  the daily signup within a range of month
        """
        args = monthQuery_parser.parse_args()
        authentication_header_parser(args['Authorization'])

        str_year = args['year']
        try:
            year = int(str_year)
        except ValueError:
            return '', http.client.BAD_REQUEST

        result = {}

        if year < 2020:
            return '', http.client.BAD_REQUEST

        for month in range(1, 13):
            user = (db.session.query(func.count(UserModel.id)).filter(
                func.extract('year', UserModel.createdAt) == year).filter(
                    func.extract('month', UserModel.createdAt) == month).all())

            result[f'{month}'] = user[0][0]

        return result


@api_namespace.route('/stat/sumquery/')
class UsersSummaryQuery(Resource):
    @api_namespace.doc('query count in db: total count')
    @api_namespace.expect(authentication_parser)
    def get(self):
        """
        Help find the sum of records in database
        """
        args = authentication_parser.parse_args()
        authentication_header_parser(args['Authorization'])
        user = (UserModel.query.count())

        return user
