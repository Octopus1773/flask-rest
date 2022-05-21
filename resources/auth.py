from flask_restful import Resource, abort, reqparse
from models.users import User
from models.revoked_tokens import RevokedToken
from app import db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt

parser = reqparse.RequestParser()
parser.add_argument('email', help='Обязательно укажите email', required=True)
parser.add_argument('password', help='Обязательно укажите пароль', required=True)


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        user = User.query.filter_by(email=data['email']).first()

        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=data['email'])
            refresh_token = create_refresh_token(identity=data['email'])
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'msg': 'Error auth'}, 401


class UserLogoutAccess(Resource):
    @jwt_required()
    def post(self):
        revoked_token = RevokedToken(jti=get_jwt()['jti'])
        db.session.add(revoked_token)
        db.session.commit()
        return {'msg': 'Ok'}


class UserLogoutRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        revoked_token = RevokedToken(jti=get_jwt()['jti'])
        db.session.add(revoked_token)
        db.session.commit()
        return {'msg': 'Ok'}


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}