"""Python Flask API Auth0 integration example
"""

from functools import wraps
import json
from os import environ as env
from six.moves.urllib.request import urlopen

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack
from flask_cors import cross_origin
from jose import jwt

from auth0.v3.authentication import GetToken
from auth0.v3 import exceptions
from auth0.v3.management import Auth0

import hashlib
import binascii

import os, sys

from collections import defaultdict

from flask_cors import CORS

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
else:
    if not os.path.isfile(os.path.join(os.getcwd(), '.env')):
        with open(os.path.join(os.getcwd(), '.env'), 'w+') as _env:
            _env.write('AUTH0_DOMAIN=\n')
            _env.write('API_IDENTIFIER=\n')
            _env.write('M2M-SEC=\n')
            _env.write('M2M-ID=\n')
            _env.write('DOMAIN=\n')
            _env.write('API_AUDIENCE=\n')
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
API_IDENTIFIER = env.get("API_IDENTIFIER")
M2M_SEC = env.get('M2M-SEC')
M2M_ID = env.get('M2M-ID')
DOMAIN = env.get('DOMAIN')
API_AUDIENCE = env.get('API_AUDIENCE')
ALGORITHMS = ["RS256"]
APP = Flask(__name__)
APP.debug = True
CORS(APP)


# Format error response and append status code.
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')
 
def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False


def requires_auth(f):
    """Determines if the access token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen(AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            print("exc 1")
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] == "HS256":
            print("exc 2")
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://"+DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                print("Exc 1")
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                print("Exc 2")
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
            except Exception:
                print("Exception 3")
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 401)
    return decorated

@APP.route('/api/roles/create', methods=['POST'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def role_creation():
    role_name = request.json['name']
    role_desc = request.json['desc']

    get_token = GetToken(DOMAIN)
    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    roles = auth0.roles
    resp = {}
    try:
        resp =  roles.create({
            'name': role_name,
            'description': role_desc
            })
    except exceptions.Auth0Error:
        return {'resp':
        {
            'error': 'Role Already exists.'
        }}
    
    return {
        'resp':
        {
            'id': resp['id'],
            'name': resp['name'],
            'desc': resp['description']
        }
    }

@APP.route('/api/users/delete', methods=['POST'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def role_deletion():
    role_id = request.json['id']

    get_token = GetToken(DOMAIN)

    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users = auth0.users

    try:
        users.delete('auth0|5d6d8e3a674ade0f285b8f10')
    except exceptions.Auth0Error:
        return {
            'resp': 
                {
                    'error': 'Role doesn\'t exist'
                }
        }

    return {
        'resp':
        {
            'success': 'Role {0} is successfully deleted'.format(role_id)
        }
    }

@APP.route('/api/roles/update', methods=['POST'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def role_updating():
    role_id = request.json['id']
    role_name = request.json['name']
    role_desc = request.json['desc']

    get_token = GetToken(DOMAIN)

    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    roles = auth0.roles

    try:
        resp = roles.update(id=role_id,
        body= {
            'name': role_name,
            'description': role_desc
        })
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'Role id, {0}, doesn\'t exist'.format(role_id)
            }
        }

    return {
        'resp': {
            'id': resp['id'],
            'name': resp['name'],
            'desc': resp['description']
        }
    }

@APP.route('/api/users/create', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def user_creation():
    user_email = request.json['email']
    user_name = request.json['name']
    user_username = request.json['username']
    user_first = user_name.split()[0]
    user_last = user_name.split()[1]
    user_password = request.json['password']

    get_token = GetToken(DOMAIN)
    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users = auth0.users
    try:
        resp = users.create({
            'email': user_email,
            'name': user_name,
            'given_name': user_first,
            'family_name': user_last,
            'username': user_username,
            'connection': 'LoginSystem',
            'password': user_password
        })
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'User already exists'
            }
        }

    return {'resp': resp}

@APP.route('/api/users/delete', methods=['POST'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def user_deletion():
    user_id = request.json['id']

    get_token = GetToken(DOMAIN)
    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users = auth0.users
    try:
        users.delete(user_id)
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'User id, {0} doesn\'t exist'.format(user_id)
            }
        }

@APP.route('/api/users/update', methods=['POST'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def user_updating():
    params = request.json
    user_id = params['id']

    get_token = GetToken(DOMAIN)

    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users = auth0.users

    user = users.get("{0}".format(user_id))

    if 'email' in params:
        user_email = params['email']
    else:
        user_email = ''

    if 'name' in params:
        user_name = params['name']
    else:
        user_name = user['name']

    user_first = user_name.split()[0]
    user_last = user_name.split()[1]
    
    if 'username' in params:
        user_username = params['username']
    else:
        user_username = ''

    if 'password' in params:
        user_password = params['password']
    else:
        user_password = None

    try:
        if user_password:

            if user_email and user_username:
                return {
                    'resp': {
                        'error': 'Cannot update user and email simultaneously'
                    }
                }
            if user_username:
                resp = users.update(user_id,
                body={
                    'name': user_name,
                    'given_name': user_first,
                    'family_name': user_last,
                    'username': user_username,
                    'connection': 'LoginSystem'
                })
            elif user_email:
                resp = users.update(user_id,
                    body={
                        'email': user_email,
                        'name': user_name,
                        'given_name': user_first,
                        'family_name': user_last,
                        'connection': 'LoginSystem'
                    })
            else:
                resp = users.update(user_id,
                    body={
                        'name': user_name,
                        'given_name': user_first,
                        'family_name': user_last,
                        'connection': 'LoginSystem'
                    })
            
        else:
            if user_email and user_username:
                return {
                    'resp': {
                        'error': 'Cannot update user and email simultaneously'
                    }
                }
            if user_username:
                resp = users.update(user_id,
                body={
                    'name': user_name,
                    'given_name': user_first,
                    'family_name': user_last,
                    'username': user_username,
                    'connection': 'LoginSystem'
                })
            elif user_email:
                resp = users.update(user_id,
                    body={
                        'email': user_email,
                        'name': user_name,
                        'given_name': user_first,
                        'family_name': user_last,
                        'connection': 'LoginSystem'
                    })
            else:
                resp = users.update(user_id,
                    body={
                        'name': user_name,
                        'given_name': user_first,
                        'family_name': user_last,
                        'connection': 'LoginSystem'
                    })
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'User id, {0}, doesn\'t exist'.format(user_id)
            }
        }

    return {
        'resp': resp
    }

@APP.route('/api/users/get', methods=['POST', 'GET'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def user_get():
    params = request.json
    user_id = params['id']

    get_token = GetToken(DOMAIN)

    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users = auth0.users

    try:
        user = users.get(user_id)
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'User ID, {0}, doesn\'t exist'.format(user_id)
            }
        }

    return {
        'resp': user
    }

@APP.route('/api/users/get_users_by_email', methods=['POST', 'GET'])
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def user_get_user_by_email():
    params = request.json
    user_email = params['email']

    get_token = GetToken(DOMAIN)

    token = get_token.client_credentials(M2M_ID,
        M2M_SEC, '{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    auth0 = Auth0(DOMAIN, mgmt_api_token)

    users_by_email = auth0.users_by_email

    try:
        users = users_by_email.search_users_by_email(user_email)
    except exceptions.Auth0Error:
        return {
            'resp': {
                'error': 'No email found by the name of {0}'.format(user_email)
            }
        }

    return {
        'resp': users
    }

@APP.route('/api/shop/get_by_id')
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def shop_get_by_id():
    pass

@APP.route('/api/shop/get_all_names_and_ids')
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def shop_get_names_ids():
    pass

@APP.route('/api/shop/create')
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def shop_create():
    pass

@APP.route('/api/shop/update')
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def shop_update():
    pass

@APP.route('/api/shop/delete')
@requires_auth
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
def shop_delete():
    pass



# Controllers API
@APP.route("/api/public")
@cross_origin(headers=["Content-Type", "Authorization"])
def public():
    """No access token required to access this route
    """
    response = "Hello from a public endpoint! You don't need to be authenticated to see this."
    return jsonify(message=response)

# @APP.route("/api/private-scoped")
# @cross_origin(headers=["Content-Type", "Authorization"])
# @cross_origin(headers=["Access-Control-Allow-Origin", "http://127.0.0.1:4200"])
# @requires_auth
# def private_scoped():
#     """A valid access token and an appropriate scope are required to access this route
#     """
#     if requires_scope("read:messages"):
#         response = "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this."
#         return jsonify(message=response)
#     raise AuthError({
#         "code": "Unauthorized",
#         "description": "You don't have access to this resource"
#     }, 403)

if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=env.get("PORT", 3010))