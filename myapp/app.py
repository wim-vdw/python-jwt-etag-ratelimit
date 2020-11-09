"""
A simple Flask application to test JWT, ETag and a custom made Rate Limiter.

Author: Wim Van den Wyngaert
"""

from flask import Flask, jsonify, request, g
from functools import wraps
from myapp.ratelimit import RateLimiter
from datetime import datetime, timedelta
import jwt

RATE_LIMIT = 5
SECRET = 'This is a secret'
VALID = 30

app = Flask(__name__)
limiter = RateLimiter(RATE_LIMIT)
blacklist = set()
sap_systems = set()
sap_systems.add('XP1')
sap_systems.add('KP1')
sap_systems.add('YP2')
sap_systems.add('LP2')


def rate_limiter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not limiter(request.remote_addr):
            return jsonify(message=f'Rate limit of {RATE_LIMIT} calls per day exceeded.'), 429
        return func(*args, **kwargs)

    return wrapper


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization')
        if not auth or not auth.startswith('Bearer '):
            return jsonify(message='Provide a Bearer token'), 401
        token = auth.removeprefix('Bearer ')
        if token in blacklist:
            return jsonify(message='Token has been blacklisted, please logon again'), 401
        try:
            decoded = jwt.decode(token, SECRET, algorithms='HS256')
            g.token = token
            g.user = decoded.get('sub')
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify(message='Token has been expired'), 401
        except jwt.exceptions.InvalidTokenError:
            return jsonify(message='Invalid taken has been provided'), 401
        return func(*args, **kwargs)

    return wrapper


@app.route('/', methods=['GET'])
def index():
    """Display a simple message in plain text."""
    return 'SAP System overview.'


@app.route('/limit', methods=['GET'])
@rate_limiter
def limit():
    """Rate limiter."""
    return jsonify(calls=limiter.status(request.remote_addr))


@app.route('/reset', methods=['POST'])
@token_required
def reset():
    """Reset rate limiter."""
    limiter.reset()
    return jsonify(message='All rate limits have been reset.')


@app.route('/sapsystems', methods=['GET'])
@token_required
def sapsystems_get():
    """Get a list of all SAP systems in JSON format."""
    local_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    utc_time = datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')
    return jsonify(sapsystems=list(sap_systems),
                   number_of_systems=len(sap_systems),
                   time_local=local_time,
                   time_utc=utc_time)


@app.route('/sapsystems/<sapsystem>', methods=['POST'])
@token_required
def sapsystem_create(sapsystem):
    """Add an SAP system to the list and return JSON result."""
    if sapsystem in sap_systems:
        return jsonify(message=f'SAP system {sapsystem} already exists'), 400
    sap_systems.add(sapsystem)
    return jsonify(message=f'SAP system {sapsystem} created successfully'), 201


@app.route('/sapsystems/<sapsystem>', methods=['DELETE'])
@token_required
def sapsystem_delete(sapsystem):
    """Delete an SAP system from the list and return JSON result."""
    if sapsystem not in sap_systems:
        return jsonify(message=f'SAP system {sapsystem} does not exist'), 400
    sap_systems.remove(sapsystem)
    return jsonify(message=f'SAP system {sapsystem} deleted successfully'), 200


@app.route('/login', methods=['POST'])
def login():
    """Perform logon via basic authentication.

    In case of successful logon a Bearer token will be returned.
    """
    auth = request.authorization
    if not auth:
        return jsonify(message='Provide logon credentials via basic authentication'), 401
    if auth.username != 'wim' or auth.password != 'pass123':
        return jsonify(message='Incorrect combination of username and password'), 401
    payload = {
        'sub': 'Wim Van den Wyngaert',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=VALID)
    }
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return jsonify(token=token.decode())


@app.route('/logout', methods=['POST'])
@token_required
def logout():
    """Perform logout."""
    blacklist.add(g.token)
    return jsonify(message='Logout successful, token has been blacklisted',
                   name=g.user,
                   token=g.token)


@app.route('/etag-if-match')
@token_required
def etag_if_match():
    ok = '4d246daa94f95db848cbc855e731f8483388c4f3dc1bfea9b1b448ae9c0b4820'
    if_match = request.if_match
    if if_match.contains(ok):
        return jsonify(message='Data has been changed')
    else:
        return jsonify(message='Someone else already changed the data'), 412


@app.route('/etag-if-none-match')
@token_required
def etag_if_none_match():
    ok = '4d246daa94f95db848cbc855e731f8483388c4f3dc1bfea9b1b448ae9c0b4820'
    if_none_match = request.if_none_match
    if if_none_match.contains(ok):
        return jsonify(message='OK'), 304
    else:
        return jsonify(message='Sending you all new data')


@app.errorhandler(404)
def page_not_found(error):
    """Overrule Flask HTML error for page not found with a JSON message."""
    return jsonify(message=str(error)), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Overrule Flask HTML error for method not allowed with a JSON message."""
    return jsonify(message=str(error)), 405
