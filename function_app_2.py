# import azure.functions as func
# import logging
# import jwt , requests
# from flask import Flask, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_restful import Api, Resource, reqparse
# from werkzeug.security import generate_password_hash, check_password_hash
# import uuid
# import jwt
# from functools import wraps 

# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# @app.route(route="user_registration_func")
# def user_registration_func(req: func.HttpRequest) -> func.HttpResponse:

#     class User(db.Model):
#         id = db.Column(db.Integer, primary_key=True)
#         public_id = db.Column(db.String(50), unique=True, nullable=False)
#         email = db.Column(db.String(50), unique=True, nullable=False)
#         password = db.Column(db.String(100), nullable=False)
#         role = db.Column(db.String(20), nullable=False)

# register_parser = reqparse.RequestParser()
# register_parser.add_argument('email', help='Email is required', required=True)
# register_parser.add_argument('password', help='Password is required', required=True)

# login_parser = reqparse.RequestParser()
# login_parser.add_argument('email', help='Email is required', required=True)
# login_parser.add_argument('password', help='Password is required', required=True)

# update_profile_parser = reqparse.RequestParser()
# update_profile_parser.add_argument('email')
# update_profile_parser.add_argument('subscription_tier')

# change_password_parser = reqparse.RequestParser()
# change_password_parser.add_argument('password', help='Password is required', required=True)

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.headers.get('Authorization')
#         if not token:
#             return {'message': 'Token is missing'}, 401
#         try:
#             token_type, token_value = token.split()
#             if token_type.lower() != 'bearer':
#                 raise ValueError('Invalid token type')
#             data = jwt.decode(token_value, app.config['SECRET_KEY'], algorithms=['HS256'])
#             current_user = User.query.filter_by(public_id=data['public_id']).first()
#         except jwt.ExpiredSignatureError:
#             return {'message': 'Token has expired'}, 401
#         except jwt.InvalidTokenError:
#             return {'message': 'Token is invalid'}, 401
#         except (ValueError, KeyError):
#             return {'message': 'Invalid token format'}, 401
#         return f(current_user, *args, **kwargs)
#     return decorated

# class UserRegistration(Resource):
#     def post(self):
#         data = register_parser.parse_args()
#         email = data.get('email')
#         password = data.get('password')
#         if User.query.filter_by(email=email).first():
#             return {'message': 'Email address already exists'}, 400
#         hashed_password = generate_password_hash(password)
#         new_user = User(public_id=str(uuid.uuid4()), email=email, password=hashed_password, role="individual")
#         try:
#             db.session.add(new_user)
#             db.session.commit()
#         except Exception as e:
#             return {'message': 'Error creating user: {}'.format(str(e))}, 500
#         return {'userId': new_user.id, 'message': 'Account created'}, 201

# class UserLogin(Resource):
#     def post(self):
#         data = login_parser.parse_args()
#         user = User.query.filter_by(email=data['email']).first()
#         if user and check_password_hash(user.password, data['password']):
#             token = jwt.encode({'public_id': user.public_id}, app.config['SECRET_KEY'], algorithm='HS256')
#             return {'token': token}, 200  # Remove .decode('utf-8') here
#         return {'message': 'Invalid email or password'}, 401


# # New endpoints
# class UserLogout(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement logout functionality here
#         return {'message': 'Successfully logged out'}, 200

# class TokenRefresh(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement token refresh functionality here
#         new_token = jwt.encode({'public_id': current_user.public_id}, app.config['SECRET_KEY'], algorithm='HS256')
#         return {'token': new_token.decode('utf-8')}, 200

# class TokenRevoke(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement token revoke functionality here
#         # This is just an example, you can invalidate the token in your database
#         return {'message': 'Token revoked'}, 200
    
# class UserProfile(Resource):
#     @token_required
#     def get(self, current_user, userId):
#         # Only admin or the user themselves can access the profile
#         if current_user.role != 'admin' and str(current_user.id) != userId:
#             return {'message': 'Unauthorized to access this resource'}, 403
#         user = User.query.filter_by(id=userId).first()
#         if not user:
#             return {'message': 'User not found'}, 404
#         user_data = {
#             'userId': user.id,
#             'email': user.email,
#             'subscriptionTier': user.subscription_tier
#         }
#         return user_data, 200

#     @token_required
# #    def put(self, current_user, userId):
#         # Only admin or the user themselves can update the profile
#         # if current_user.role != 'admin' and str(current_user.id) != userId:
#         #     return {'message': 'Unauthorized to access this resource'}, 403
#         # data = update_profile_parser.parse_args()
#         # user = User.query.filter_by(id=userId).first()
#         # if not user:
#         #     return {'message': 'User not found'}, 404
#         # if data.get('email'):
#         #     user.email = data['email']
#         # if data.get('subscription_tier'):
#         #     user.subscription_tier = data['subscription_tier']
#         # try:
#         #     db.session.commit()
#         #     return {'message': 'Profile updated successfully'}, 200
#         # except Exception as e:
#         #     return {'message': 'Error updating profile: {}'.format(str(e))}, 500

# #class UserChangePassword(Resource):
#     # @token_required
#     # def put(self, current_user, userId):
#     #     # Only the user themselves can change their password
#     #     if str(current_user.id) != userId:
#     #         return {'message': 'Unauthorized to access this resource'}, 403
#     #     data = change_password_parser.parse_args()
#     #     user = User.query.filter_by(id=userId).first()
#     #     if not user:
#     #         return {'message': 'User not found'}, 404
#     #     hashed_password = generate_password_hash(data['password'])
#     #     user.password = hashed_password
#     #     try:
#     #         db.session.commit()
#     #         return {'message': 'Password changed'}, 200
#     #     except Exception as e:
#     #         return {'message': 'Error changing password: {}'.format(str(e))}, 500

# import azure.functions as func
# import jwt , json
# from werkzeug.security import generate_password_hash, check_password_hash
# from sqlalchemy import Column, String, Integer, create_engine
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker
# import uuid
# from functools import wraps

# Base = declarative_base()

# class User(Base):
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True)
#     public_id = Column(String(50), unique=True, nullable=False)
#     email = Column(String(50), unique=True, nullable=False)
#     password = Column(String(100), nullable=False)
#     role = Column(String(20), nullable=False)

# engine = create_engine('sqlite:///:memory:', echo=True)
# Base.metadata.create_all(engine)
# Session = sessionmaker(bind=engine)

# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR = "user_registration_func"
# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR = "user_logout"
# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR = "token_refresh"
# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR = "token_revoke"
# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR = "user_profile"
# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
# ROUTE_VAR= "change_password"


# def fetch_user_data(email):
#     session = Session()
#     user = session.query(User).filter_by(email=email).first()
#     session.close()
#     return user

# @app.route(route="user_registration_func", auth_level=func.AuthLevel.ANONYMOUS)
# def user_registration_func(req: func.HttpRequest) -> func.HttpResponse:
#     if req.method == 'POST':
#         req_body = req.get_json()
#         email = req_body.get('email')
#         password = req_body.get('password')
#         if not email or not password:
#             return func.HttpResponse("Email and password are required", status_code=400)
#         session = Session()
#         if session.query(User).filter_by(email=email).first():
#             session.close()
#             return func.HttpResponse("Email address already exists", status_code=400)
#         hashed_password = generate_password_hash(password)
#         new_user = User(public_id=str(uuid.uuid4()), email=email, password=hashed_password, role="individual")
#         session.add(new_user)
#         session.commit()
#         session.close()
#         return func.HttpResponse("Account created", status_code=201)
#     else:
#         return func.HttpResponse("Method not allowed", status_code=405)


# def route(route, auth_level):
#     def decorator(func):
#         def wrapper(req: func.HttpRequest):
#             if req.route_params and 'route' in req.route_params and req.route_params['route'] == route:
#                 if auth_level == func.AuthLevel.ANONYMOUS or req.params.get('auth_level') == auth_level:
#                     return func(req)
#                 else:
#                     return func.HttpResponse("Unauthorized", status_code=401)
#             else:
#                 return func.HttpResponse("Not Found", status_code=404)
#         return wrapper
#     return decorator

# @app.route(route="user_login", auth_level=func.AuthLevel.ANONYMOUS)
# def user_login(req: func.HttpRequest) -> func.HttpResponse:
#     if req.method == 'POST':
#         req_body = req.get_json()
#         email = req_body.get('email')
#         password = req_body.get('password')
#         if not email or not password:
#             return func.HttpResponse("Email and password are required", status_code=400)
#         user = fetch_user_data(email)
#         if user and check_password_hash(user.password, password):
#             token = jwt.encode({'public_id': user.public_id}, "YOUR_SECRET_KEY", algorithm='HS256')
#             return func.HttpResponse(token, status_code=200)
#         else:
#             return func.HttpResponse("Invalid email or password", status_code=401)
#     else:
#         return func.HttpResponse("Method not allowed", status_code=405)


# def token_required(f):
#     @wraps(f)
#     def decorated_function(req: func.HttpRequest):
#         token = req.headers.get('Authorization')
#         if not token:
#             return func.HttpResponse("Token is missing", status_code=401)
#         try:
#             token_type, token_value = token.split()
#             if token_type.lower() != 'bearer':
#                 raise ValueError('Invalid token type')
#             data = jwt.decode(token_value, "YOUR_SECRET_KEY", algorithms=['HS256'])
#             # Assuming you have the logic to retrieve user data from the token
#             current_user = fetch_user_data(data['public_id'])
#         except jwt.ExpiredSignatureError:
#             return func.HttpResponse("Token has expired", status_code=401)
#         except jwt.InvalidTokenError:
#             return func.HttpResponse("Token is invalid", status_code=401)
#         except (ValueError, KeyError):
#             return func.HttpResponse("Invalid token format", status_code=401)
#         return f(req, current_user)  # Assuming you pass current_user here
#     return decorated_function

# @app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
# def user_logout(req: func.HttpRequest, current_user) -> func.HttpResponse:
#     if req.method == 'POST':
#         # Implement logout functionality here
#         return func.HttpResponse("Successfully logged out", status_code=200)
#     else:
#         return func.HttpResponse("Method not allowed", status_code=405)

# @app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
# def token_refresh(req: func.HttpRequest) -> func.HttpResponse:
#     if req.method == 'POST':
#         # Implement token refresh functionality here
#         return func.HttpResponse("Token refresh endpoint", status_code=200)
#     else:
#         return func.HttpResponse("Method not allowed", status_code=405)


# @app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
# def token_revoke(req: func.HttpRequest) -> func.HttpResponse:
#     # Check if Authorization header is present
#     token_revoked = False
#     if 'Authorization' not in req.headers:
#         return func.HttpResponse("Authorization header is missing", status_code=401)
    
#     # Extract the token from Authorization header
#     auth_header = req.headers['Authorization']
#     token_type, token_value = auth_header.split(' ')
    
#     # Check if the token type is Bearer
#     if token_type.lower() != 'bearer':
#         return func.HttpResponse("Invalid token type", status_code=401)
    
#     # Decode the token
#     try:
#         decoded_token = jwt.decode(token_value, "YOUR_SECRET_KEY", algorithms=['HS256'])
#         # Assuming you have some logic to revoke the token in your system/database
#         # Example: token_revoked = revoke_token(decoded_token['token_id'])
#         # Check if the token is successfully revoked
#         if token_revoked:
#             return func.HttpResponse("Token revoked successfully", status_code=200)
#         else:
#             return func.HttpResponse("Failed to revoke token", status_code=500)
#     except jwt.ExpiredSignatureError:
#         return func.HttpResponse("Token has expired", status_code=401)
#     except jwt.InvalidTokenError:
#         return func.HttpResponse("Invalid token", status_code=401)
#     except Exception as e:
#         return func.HttpResponse(f"Error: {str(e)}", status_code=500)


# @app.route(route=ROUTE_VAR, methods=['GET'], auth_level=func.AuthLevel.ANONYMOUS)
# def user_profile(req: func.HttpRequest) -> func.HttpResponse:
#     # Retrieve user ID from query parameters
#     mock_users = {}
#     user_id = req.params.get('user_id')

#     if not user_id:
#         return func.HttpResponse("User ID is required", status_code=400)

#     # Assuming user data is retrieved from a database based on the user ID
#     user_data = mock_users.get(user_id)

#     if not user_data:
#         return func.HttpResponse("User not found", status_code=404)

#     # Return user data as JSON response
#     return func.HttpResponse(json.dumps(user_data), status_code=200, mimetype="application/json")

# @app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
# def change_password(req: func.HttpRequest) -> func.HttpResponse:
#     return func.HttpResponse("Change password endpoint", status_code=200)


# # @app.route(route="user_login", auth_level=func.AuthLevel.ANONYMOUS)
# # def user_login(req: func.HttpRequest) -> func.HttpResponse:
# #     logging.info('Python HTTP trigger function processed a request.')

# #     name = req.params.get('name')
#     if not name:
#         try:
#             req_body = req.get_json()
#         except ValueError:
#             pass
#         else:
#             name = req_body.get('name')

#     if name:
#         return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
#     else:
#         return func.HttpResponse(
#              "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
#              status_code=200
#         )
# import azure.functions as func
# import logging
# import jwt , requests
# from flask import Flask, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_restful import Api, Resource, reqparse
# from werkzeug.security import generate_password_hash, check_password_hash
# import uuid
# import jwt
# from functools import wraps 

# app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# @app.route(route="user_registration_func")
# def user_registration_func(req: func.HttpRequest) -> func.HttpResponse:

#     class User(db.Model):
#         id = db.Column(db.Integer, primary_key=True)
#         public_id = db.Column(db.String(50), unique=True, nullable=False)
#         email = db.Column(db.String(50), unique=True, nullable=False)
#         password = db.Column(db.String(100), nullable=False)
#         role = db.Column(db.String(20), nullable=False)

# register_parser = reqparse.RequestParser()
# register_parser.add_argument('email', help='Email is required', required=True)
# register_parser.add_argument('password', help='Password is required', required=True)

# login_parser = reqparse.RequestParser()
# login_parser.add_argument('email', help='Email is required', required=True)
# login_parser.add_argument('password', help='Password is required', required=True)

# update_profile_parser = reqparse.RequestParser()
# update_profile_parser.add_argument('email')
# update_profile_parser.add_argument('subscription_tier')

# change_password_parser = reqparse.RequestParser()
# change_password_parser.add_argument('password', help='Password is required', required=True)

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = request.headers.get('Authorization')
#         if not token:
#             return {'message': 'Token is missing'}, 401
#         try:
#             token_type, token_value = token.split()
#             if token_type.lower() != 'bearer':
#                 raise ValueError('Invalid token type')
#             data = jwt.decode(token_value, app.config['SECRET_KEY'], algorithms=['HS256'])
#             current_user = User.query.filter_by(public_id=data['public_id']).first()
#         except jwt.ExpiredSignatureError:
#             return {'message': 'Token has expired'}, 401
#         except jwt.InvalidTokenError:
#             return {'message': 'Token is invalid'}, 401
#         except (ValueError, KeyError):
#             return {'message': 'Invalid token format'}, 401
#         return f(current_user, *args, **kwargs)
#     return decorated

# class UserRegistration(Resource):
#     def post(self):
#         data = register_parser.parse_args()
#         email = data.get('email')
#         password = data.get('password')
#         if User.query.filter_by(email=email).first():
#             return {'message': 'Email address already exists'}, 400
#         hashed_password = generate_password_hash(password)
#         new_user = User(public_id=str(uuid.uuid4()), email=email, password=hashed_password, role="individual")
#         try:
#             db.session.add(new_user)
#             db.session.commit()
#         except Exception as e:
#             return {'message': 'Error creating user: {}'.format(str(e))}, 500
#         return {'userId': new_user.id, 'message': 'Account created'}, 201

# class UserLogin(Resource):
#     def post(self):
#         data = login_parser.parse_args()
#         user = User.query.filter_by(email=data['email']).first()
#         if user and check_password_hash(user.password, data['password']):
#             token = jwt.encode({'public_id': user.public_id}, app.config['SECRET_KEY'], algorithm='HS256')
#             return {'token': token}, 200  # Remove .decode('utf-8') here
#         return {'message': 'Invalid email or password'}, 401


# # New endpoints
# class UserLogout(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement logout functionality here
#         return {'message': 'Successfully logged out'}, 200

# class TokenRefresh(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement token refresh functionality here
#         new_token = jwt.encode({'public_id': current_user.public_id}, app.config['SECRET_KEY'], algorithm='HS256')
#         return {'token': new_token.decode('utf-8')}, 200

# class TokenRevoke(Resource):
#     @token_required
#     def post(self, current_user):
#         # Implement token revoke functionality here
#         # This is just an example, you can invalidate the token in your database
#         return {'message': 'Token revoked'}, 200
    
# class UserProfile(Resource):
#     @token_required
#     def get(self, current_user, userId):
#         # Only admin or the user themselves can access the profile
#         if current_user.role != 'admin' and str(current_user.id) != userId:
#             return {'message': 'Unauthorized to access this resource'}, 403
#         user = User.query.filter_by(id=userId).first()
#         if not user:
#             return {'message': 'User not found'}, 404
#         user_data = {
#             'userId': user.id,
#             'email': user.email,
#             'subscriptionTier': user.subscription_tier
#         }
#         return user_data, 200

#     @token_required
# #    def put(self, current_user, userId):
#         # Only admin or the user themselves can update the profile
#         # if current_user.role != 'admin' and str(current_user.id) != userId:
#         #     return {'message': 'Unauthorized to access this resource'}, 403
#         # data = update_profile_parser.parse_args()
#         # user = User.query.filter_by(id=userId).first()
#         # if not user:
#         #     return {'message': 'User not found'}, 404
#         # if data.get('email'):
#         #     user.email = data['email']
#         # if data.get('subscription_tier'):
#         #     user.subscription_tier = data['subscription_tier']
#         # try:
#         #     db.session.commit()
#         #     return {'message': 'Profile updated successfully'}, 200
#         # except Exception as e:
#         #     return {'message': 'Error updating profile: {}'.format(str(e))}, 500

# #class UserChangePassword(Resource):
#     # @token_required
#     # def put(self, current_user, userId):
#     #     # Only the user themselves can change their password
#     #     if str(current_user.id) != userId:
#     #         return {'message': 'Unauthorized to access this resource'}, 403
#     #     data = change_password_parser.parse_args()
#     #     user = User.query.filter_by(id=userId).first()
#     #     if not user:
#     #         return {'message': 'User not found'}, 404
#     #     hashed_password = generate_password_hash(data['password'])
#     #     user.password = hashed_password
#     #     try:
#     #         db.session.commit()
#     #         return {'message': 'Password changed'}, 200
#     #     except Exception as e:
#     #         return {'message': 'Error changing password: {}'.format(str(e))}, 500


import azure.functions as func
import jwt, json
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, String, Integer, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uuid
from functools import wraps

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), unique=True, nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)

engine = create_engine('sqlite:///:memory:', echo=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
ROUTE_VAR = "user_registration_func"

def fetch_user_data(email):
    session = Session()
    user = session.query(User).filter_by(email=email).first()
    session.close()
    return user

def route(route, auth_level):
    def decorator(func):
        def wrapper(req: func.HttpRequest):
            if req.route_params and 'route' in req.route_params and req.route_params['route'] == route:
                if auth_level == func.AuthLevel.ANONYMOUS or req.params.get('auth_level') == auth_level:
                    return func(req)
                else:
                    return func.HttpResponse("Unauthorized", status_code=401)
            else:
                return func.HttpResponse("Not Found", status_code=404)
        return wrapper
    return decorator

@app.route(route="user_registration_func", auth_level=func.AuthLevel.ANONYMOUS)
def user_registration_func(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == 'POST':
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')
        if not email or not password:
            return func.HttpResponse("Email and password are required", status_code=400)
        session = Session()
        if session.query(User).filter_by(email=email).first():
            session.close()
            return func.HttpResponse("Email address already exists", status_code=400)
        hashed_password = generate_password_hash(password)
        new_user = User(public_id=str(uuid.uuid4()), email=email, password=hashed_password, role="individual")
        session.add(new_user)
        session.commit()
        session.close()
        return func.HttpResponse("Account created", status_code=201)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)


@app.route(route="user_login", auth_level=func.AuthLevel.ANONYMOUS)
def user_login(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == 'POST':
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')
        if not email or not password:
            return func.HttpResponse("Email and password are required", status_code=400)
        user = fetch_user_data(email)
        if user and check_password_hash(user.password, password):
            token = jwt.encode({'public_id': user.public_id}, "YOUR_SECRET_KEY", algorithm='HS256')
            return func.HttpResponse(token, status_code=200)
        else:
            return func.HttpResponse("Invalid email or password", status_code=401)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)


def token_required(f):
    @wraps(f)
    def decorated_function(req: func.HttpRequest):
        token = req.headers.get('Authorization')
        if not token:
            return func.HttpResponse("Token is missing", status_code=401)
        try:
            token_type, token_value = token.split()
            if token_type.lower() != 'bearer':
                raise ValueError('Invalid token type')
            data = jwt.decode(token_value, "YOUR_SECRET_KEY", algorithms=['HS256'])
            # Assuming you have the logic to retrieve user data from the token
            current_user = fetch_user_data(data['public_id'])
        except jwt.ExpiredSignatureError:
            return func.HttpResponse("Token has expired", status_code=401)
        except jwt.InvalidTokenError:
            return func.HttpResponse("Token is invalid", status_code=401)
        except (ValueError, KeyError):
            return func.HttpResponse("Invalid token format", status_code=401)
        return f(req, current_user)  # Assuming you pass current_user here
    return decorated_function

@app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
def user_logout(req: func.HttpRequest, current_user) -> func.HttpResponse:
    if req.method == 'POST':
        # Implement logout functionality here
        return func.HttpResponse("Successfully logged out", status_code=200)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)

@app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
def token_refresh(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == 'POST':
        # Implement token refresh functionality here
        return func.HttpResponse("Token refresh endpoint", status_code=200)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)


@app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
def token_revoke(req: func.HttpRequest) -> func.HttpResponse:
    # Check if Authorization header is present
    token_revoked = False
    if 'Authorization' not in req.headers:
        return func.HttpResponse("Authorization header is missing", status_code=401)
    
    # Extract the token from Authorization header
    auth_header = req.headers['Authorization']
    token_type, token_value = auth_header.split(' ')
    
    # Check if the token type is Bearer
    if token_type.lower() != 'bearer':
        return func.HttpResponse("Invalid token type", status_code=401)
    
    # Decode the token
    try:
        decoded_token = jwt.decode(token_value, "YOUR_SECRET_KEY", algorithms=['HS256'])
        # Assuming you have some logic to revoke the token in your system/database
        # Example: token_revoked = revoke_token(decoded_token['token_id'])
        # Check if the token is successfully revoked
        if token_revoked:
            return func.HttpResponse("Token revoked successfully", status_code=200)
        else:
            return func.HttpResponse("Failed to revoke token", status_code=500)
    except jwt.ExpiredSignatureError:
        return func.HttpResponse("Token has expired", status_code=401)
    except jwt.InvalidTokenError:
        return func.HttpResponse("Invalid token", status_code=401)
    except Exception as e:
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)


@app.route(route=ROUTE_VAR, methods=['GET'], auth_level=func.AuthLevel.ANONYMOUS)
def user_profile(req: func.HttpRequest) -> func.HttpResponse:
    # Retrieve user ID from query parameters
    mock_users = {}
    user_id = req.params.get('user_id')

    if not user_id:
        return func.HttpResponse("User ID is required", status_code=400)

    # Assuming user data is retrieved from a database based on the user ID
    user_data = mock_users.get(user_id)

    if not user_data:
        return func.HttpResponse("User not found", status_code=404)

    # Return user data as JSON response
    return func.HttpResponse(json.dumps(user_data), status_code=200, mimetype="application/json")

@app.route(route=ROUTE_VAR, methods=['POST'], auth_level=func.AuthLevel.ANONYMOUS)
def change_password(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("Change password endpoint", status_code=200)


# @app.route(route="user_login", auth_level=func.AuthLevel.ANONYMOUS)
# def user_login(req: func.HttpRequest) -> func.HttpResponse:
#     logging.info('Python HTTP trigger function processed a request.')

#     name = req.params.get('name')
#     if not name:
#         try:
#             req_body = req.get_json()
#         except ValueError:
#             pass
#         else:
#             name = req_body.get('name')

#     if name:
#         return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
#     else:
#         return func.HttpResponse(
#              "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
#              status_code=200
#         )