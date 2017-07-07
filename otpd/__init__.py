from flask import Flask, request, json, Response

# Exceptions
from sqlalchemy.exc import IntegrityError

import binascii
import pyotp
import logging

from otpd.model import db, Client, User, TOTP, HOTP

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///otpd.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
db.create_all(app=app)

def response_msg(status, response):
    response_json = {
        'status': status,
        'response': response
    }
    r = Response(
        response=json.dumps(response_json),
        mimetype='application/json',
        status=status
    )

    return r

def validate_client(name, key):

    try:
        logger.debug("Validating for {} with {}...".format(name, key))
        client = Client.query.filter_by(name=name, key=key).first()

        if not client:
            logger.info("Validation for {} failed".format(name))
            return False
        else:
            logger.info("Validation for {} succeeded".format(name))
            return True
    except:
        raise


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/user/create', methods = ['POST'])
def user_create():

    # Make sure the request has the correct application type
    if request.headers['Content-Type'] == 'application/json':

        try:
            # Get values from posted JSON message
            data = request.json
            user = data['user']

            # Create the user
            new_user = User(username=user)
            db.session.add(new_user)
            db.session.commit()

            # User created, return success
            response = 'User {user} created.'.format(user=user)
            return response_msg(201, response)

        except KeyError as e:
            # We're missing a required field
            error = 'Missing required field'
            return response_msg(400, error)
        except IntegrityError as e:
            # User already exists
            error = 'User {user} already exists'.format(user=user)
            return response_msg(409, error)

    else:
        return 'Bad request', 400

def user_get(user):
    # Get HOTP/TOTP tokens associated with this user
    totps = []
    hotps = []

    for totp in TOTP.query.filter_by(user_id=user.id):
        totps.append({
            'id': totp.id,
            'name': totp.name,
            'enabled': totp.enabled
        })

    for hotp in HOTP.query.filter_by(user_id=user.id):
        hotps.append({
            'id': hotp.id,
            'name': hotp.name,
            'enabled': hotp.enabled
        })

    user_details = {
        'id': user.id,
        'username': user.username,
        'tokens': {
            'totp': totps,
            'hotp': hotps
        }
    }

    return user_details

@app.route('/user/<int:id>', methods = ['GET'])
def user_get_by_id(id):
    # Check content-type
    user = User.query.filter_by(id=id).first()

    if not user:
        return response_msg(404, 'User not found')

    response = user_get(user)

    return response_msg(200, response)

@app.route('/user/list', methods = ['GET'])
def user_list():
    try:
        users = []
        for user in User.query.all():
            users.append(user.username)

        response = {
            "users": users
        }
        return response_msg(200, response)
    except:
        raise

@app.route('/user/<int:id>/validate', methods = ['POST'])
def user_validate(id):
    if request.headers['Content-Type'] != 'application/json':
        return response_msg(400, 'Bad request')

    try:
        data = request.json

        token = data['token']

        user = User.query.filter_by(id=id).first()

        if not user:
            return response_msg(404, 'User not found')

        # Validate against TOTPs
        for totp in TOTP.query.filter_by(user_id=user.id):
            if totp.validate(token):
                return response_msg(200, 'Validation succeeded')
        else:
            return response_msg(403, 'Validation failed')

    except:
        raise


@app.route('/verify', methods = ['POST'])
def verify():
    # Make sure the request has the correct application type
    if request.headers['Content-Type'] == 'application/json':

        try:
            # Get values from posted JSON message
            data = request.json
            user = data['user']
            token = data['token']

            return 'Verifying OTP {} for {}'.format(user, token)

        except KeyError as e:
            return 'Bad request', 400

    else:
        return 'Bad request', 400

@app.route('/generate')
def generate():
    base32_secret = pyotp.random_base32()

    return response_msg(200, base32_secret)

@app.route('/totp/<int:id>/current')
def totp_current(id):
    try:
        totp = TOTP.query.filter_by(id=id).first()

        if not totp:
            return response_msg(404, 'TOTP not found')

        otp = pyotp.TOTP(totp.secret)

        return response_msg(200, str(otp.now()))
    except:
        raise

@app.route('/totp/<int:id>/enable')
def totp_enable(id):
    """Enable TOTP"""
    try:
        totp = TOTP.query.filter_by(id=id).first()

        if not totp:
            # TOTP not found
            logger.error('TOTP {id} not found.'.format(id=id))
            return response_msg(404, 'TOTP not found')

        # Enable TOTP
        logger.info('Enabling TOTP {id}...'.format(id=id))
        totp.enable()

        return response_msg(200, 'TOTP enabled')

    except:
        # TODO - catch proper exception
        raise


@app.route('/totp/<int:id>/disable')
def totp_disable(id):
    """Disable TOTP"""
    try:
        totp = TOTP.query.filter_by(id=id).first()

        if not totp:
            # TOTP not found
            logger.error('TOTP {id} not found.'.format(id=id))
            return response_msg(404, 'TOTP not found')

        # Enable TOTP
        logger.info('Disabling TOTP {id}...'.format(id=id))
        totp.disable()

        return response_msg(200, 'TOTP disabled')

    except:
        # TODO - catch proper exception
        raise

@app.route('/totp/<int:id>/validate', methods = ['POST'])
def totp_validate(id):
    if request.headers['Content-Type'] == 'application/json':
        try:
            data = request.json
            token = data['token']

            totp = TOTP.query.filter_by(id=id).first()

            if not totp:
                return response_msg(404, 'TOTP not found')

            otp = pyotp.TOTP(totp.secret)
            current_token = str(otp.now())

            if not totp.enabled:
                return response_msg(403, 'TOTP disabled')

            if token == current_token:
                if totp.last_successful == current_token:
                    return response_msg(403, 'TOTP replayed')
                else:
                    totp.last_successful = current_token
                    db.session.add(totp)
                    db.session.commit()
                    return response_msg(200, 'OK')
            else:
                return response_msg(403, 'TOTP incorrect')
        except:
            raise

    else:
        return response_msg(400, 'Bad request')

@app.route('/totp/<int:id>/associate', methods = ['POST'])
def totp_associate(id):
    # Check content-type
    if not request.headers['Content-Type'] == 'application/json':
        return response_msg(400, 'Bad request')

    try:
        data = request.json

        totp = TOTP.query.filter_by(id=id).first()

        if not totp:
            return response_msg(404, 'TOTP not found')

        if totp.user_id:
            return response_msg(409, 'TOTP association already exists')

        user = User.query.filter_by(id=data['user_id']).first()

        if not user:
            return response_msg(404, 'User not found')

        totp.user_id = user.id
        db.session.add(totp)
        db.session.commit()

        return response_msg(200, 'TOTP association created')

    except KeyError as e:
        return response_msg(400, 'Missing required field')
    except:
        raise

@app.route('/totp/<int:id>/disasssociate', methods = ['POST'])
def totp_disassociate(id):

    # Check content-type
    if not request.headers['Content-Type'] == 'application/json':
        return response_msg(400, 'Bad request')

    pass

@app.route('/totp/create', methods = ['POST'])
def totp_create():
    """Create a TOTP"""
    # Make sure the request has the correct application type
    if request.headers['Content-Type'] == 'application/json':

        try:
            # Get data from the JSON request
            data = request.json
            name = data['name']

            # Create a new TOTP object and populate it
            new_totp = TOTP()
            new_totp.secret = pyotp.random_base32()
            new_totp.name = name

            # Create a pyotp object to generate the URI
            otp = pyotp.TOTP(new_totp.secret)

            # Save our new TOTP to the DB
            db.session.add(new_totp)
            db.session.commit()

            # Build response
            response = {
                'id': new_totp.id,
                'name': new_totp.name,
                'secret': new_totp.secret,
                'url': otp.provisioning_uri(name)
            }

            # Return response
            return response_msg(201, response)

        except KeyError as e:
            # We're missing a required field
            return response_msg(400, 'Missing required field')

@app.route('/totp/list', methods = ['GET'])
def totp_list():
    try:
        totps = []
        for totp in TOTP.query.all():
            totps.append({'id': totp.id, 'name': totp.name})

        return response_msg(200, totps)
    except:
        raise

@app.route('/totp/<int:id>', methods = ['GET'])
def totp_get(id):
    try:
        totp = TOTP.query.filter_by(id=id).first()

        if not totp:
            return response_msg(404, 'TOTP not found')

        response = {
            'id': totp.id,
            'name': totp.name
        }

        return response_msg(200, response)
    except:
        raise

if __name__ == '__main__':
    logging.basicConfig(
        filename='otpd.log',
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)-8s %(name)-12s/%(funcName)-16s %(message)s'
    )
    logger = logging.getLogger(__name__)
    logger.info('Starting...')
    app.run(host="0.0.0.0")
