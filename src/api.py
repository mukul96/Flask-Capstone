import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS


import datetime
import jwt


JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def create_app(test_config=None):
    app = Flask(__name__)
    setup_db(app)
    # Set up CORS
    CORS(app)

    def require_jwt(function):
        """
        Decorator to check valid jwt is present.
        """
        @functools.wraps(function)
        def decorated_function(*args, **kws):
            if not 'Authorization' in request.headers:
                abort(401)
            data = request.headers['Authorization']
            token = str.replace(str(data), 'Bearer ', '')
            try:
                jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            except:  # pylint: disable=bare-except
                abort(401)

            return function(*args, **kws)
        return decorated_function


    @app.route('/', methods=['POST', 'GET'])
    def health():
        return jsonify("Healthy")


    @app.route('/auth', methods=['POST'])
    def auth():
        """
        Create JWT token based on email.
        """
        request_data = request.get_json()
        print(request_data)
        email = request_data.get('email')
        password = request_data.get('password')
        if not email:
        
            return jsonify({"message": "Missing parameter: email"}, 400)
        if not password:
        
            return jsonify({"message": "Missing parameter: password"}, 400)
        body = {'email': email, 'password': password}

        user_data = body

        return jsonify(token=_get_jwt(user_data).decode('utf-8'))


    @app.route('/contents', methods=['GET'])
    def decode_jwt():
        """
        Check user token and return non-secret data
        """
        if not 'Authorization' in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = str.replace(str(data), 'Bearer ', '')
        print(token)
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except:  # pylint: disable=bare-except
            abort(401)

        response = {'email': data['email'],
                    'exp': data['exp'],
                    'nbf': data['nbf']}
        return jsonify(**response)


    def _get_jwt(user_data):
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
        payload = {'exp': exp_time,
                 'nbf': datetime.datetime.utcnow(),
                'email': user_data['email']}
        return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

    return app


APP = create_app()


if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8080, debug=True)
