#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    def post(self):
        fields = request.get_json()
        username = fields['username']
        password = fields['password']

        if username and password:
            new_user = User(username=username)
            new_user.password_hash = password
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id

            result = make_response(
                new_user.to_dict(),
                201
            )

        else:
            result = make_response(
                {'error': '422 Unprocessable Entity'},
                422
            )

        return result        

class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            result = make_response(
                user.to_dict(),
                200
            )

        else:
            result = make_response(
                {},
                204
            )

        return result

class Login(Resource):
    def post(self):
        fields = request.get_json()
        username = fields['username']
        password = fields['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            result = make_response(
                user.to_dict(),
                200
            )

        else:
            result = make_response(
                {'error': '401 Unauthorized'},
                401
            )

        return result

class Logout(Resource):
    def delete(self):
        session['user_id'] = None

        result = make_response(
            {},
            204
        )

        return result

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
