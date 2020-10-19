import os
import secrets
import base64
import jwt

import log
from usersJsonAuthenticator import UsersJsonAuthenticator


class UserAuth:
    """User authentication.

    This implementation is backward compatible with origina pvServer
    and it is not very safe as it
    """
    def __init__(self, salt, authenticator):
        """Constructor

        Parameters
        ----------
        salt : string
            Salt used to build JWT hash.
        authenticator : Authenticator
            User authentication engine.
        """
        self.timestamp = '0'
        self.knownUsers = {}
        self.secretKey = None
        self.salt = salt
        self.authenticator = authenticator

    def loadSecretKey(self, secretKeyFile):
        try:
            with open(secretKeyFile, 'r') as f:
                self.secretKey = f.readline().strip()
        except:
            log.warning('Secret key is auto-generated. This invalidates all JWT issued earlier.')
            self.secretKey = secrets.token_urlsafe(16)

    def addUser(self, knownUsers, userInfo, pepper):
        # Backward compatibility code
        jwtId = jwt.encode({'id': str(userInfo)+pepper+self.salt},
                           self.secretKey, algorithm='HS256').decode('utf-8')
        knownUsers[jwtId] = userInfo
        return jwtId

    def hashUsers(self, users, timestamp):
        try:
            timestamp = str(timestamp)
            knownUsers = {}
            for userid in users:
                self.addUser(knownUsers, userid, timestamp)
            return knownUsers
        except:
            log.exception(
                'Exception while creating JWT lookup table. No user will be allowed.')
            return {}

    def connect(self):
        try:
            users, timestamp = self.authenticator.connect()
            self.loadDict(users, timestamp)
        except:
            log.exception(
                'Exception while loading users.json. No user will be allowed.')
            self.knownUsers = {}
            self.timestamp = '0'

    def loadDict(self, users, timestamp):
        self.timestamp = str(timestamp)
        self.knownUsers = self.hashUsers(users, timestamp)

    def authenticate(self, username, password):
        if not username or not password:
            return None
        for jwtId, userInfo in self.knownUsers.items():
            if username == userInfo.get('username', None):
                if self.authenticator.authenticate(username, password, userInfo) is not None:
                    return jwtId
                else:
                    return None
        userInfo = self.authenticator.authenticate(username, password, None)
        if userInfo is not None:
            return self.addUser(self.knownUsers, userInfo, self.timestamp)
        return None

    def find_authorized(self, jwtId):
        info = self.knownUsers.get(jwtId, None)
        return info.get('username', None) if info is not None else None


def init(salt, secretKeyFile, usersJsonFile, authenticator):
    """Initialize user authentication

    Parameters
    ----------
    salt : str
        Salt used to build JWT.
    secretKeyFile : str, optional
        Location of a file containing a secret key.
        If not found, the key will be generated.
    usersJsonFile : str, optional
        Location of a file `users.json`.
    authenticator : Authenticator
        Instance of the authenticating engine.
    """
    instance = UserAuth(
        salt,
        UsersJsonAuthenticator(usersJsonFile) if authenticator is None else authenticator)
    instance.loadSecretKey(secretKeyFile)
    instance.connect()
    return instance
