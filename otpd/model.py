from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from Crypto.Hash import SHA256

import pyotp
import logging

logger = logging.getLogger(__name__)

db = SQLAlchemy()

class Client(db.Model):
    """Client model"""
    __tablename__ = 'client'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    key = db.Column(db.String(64), unique=False)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Client: {}>'.format(self.name)

class User(db.Model):
    """User model"""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)

    totps = db.relationship('TOTP')
    hotps = db.relationship('HOTP')

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return '<User: {}>'.format(self.username)

class TOTP(db.Model):
    """TOTP model"""
    __tablename__ = 'totp'

    #user = db.relationship('User',
    #                       backref=db.backref('users', lazy=True))

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=True)
    secret = db.Column(db.String(256), unique=False)
    enabled = db.Column(db.Boolean, default=True)
    last_successful = db.Column(db.String(6), unique=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<TOTP: {}/{}>'.format(self.id, self.name)

    def enable(self):
        """Enable TOTP"""
        self.enabled = True
        db.session.add(self)
        db.session.commit()

        logger.info("Disabled TOTP {id}".format(id=self.id))

    def disable(self):
        """Disable TOTP"""
        self.enabled = False
        db.session.add(self)
        db.session.commit()

        logger.info("Enabled TOTP {id}".format(id=self.id))

    def validate(self, token):
        """Validate token against the TOTP"""
        otp = pyotp.TOTP(self.secret)
        current_token = str(otp.now())

        logger.debug("Validating token against TOTP {id}".format(id=self.id))

        # Check to see if the TOTP is enabled
        if not self.enabled:
            logger.info("TOTP {id} is disabled".format(id=self.id))
            return False

        # Check to see if the token matches our calculated token
        if token == current_token:

            # Check to see if this is the same as the last successful token
            if token == self.last_successful:
                # Token has been used already
                logger.info("Current token for TOTP {id} has already been used".format(id=self.id))
                return False

            self.last_successful = token
            db.session.add(self)
            db.session.commit()
            logger.info("Token validated for TOTP {id}".format(id=self.id))
            return True

        logger.info("Token for TOTP {id} is not valid".format(id=self.id))
        return False

class HOTP(db.Model):
    """HOTP model"""
    __tablename__ = 'hotp'

    #user = db.relationship('User',
    #                       backref=db.backref('users', lazy=True))

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=True)
    secret = db.Column(db.String(256), unique=False)
    counter = db.Column(db.Integer, default=0)
    enabled = db.Column(db.Boolean, default=True)
    last_successful = db.Column(db.String(6), unique=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<HOTP: {}/{}>'.format(self.id, self.name)