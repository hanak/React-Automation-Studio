import os
import json
import bcrypt
from authenticator import Authenticator

class UsersJsonAuthenticator(Authenticator):
    """Authentication based on a JSON file
    containing all valid users.

    Example JSON file:
    ```
    {
        "users": [
            {
                "username": "user",
                "password": "password hashed using bcrypt"
            }
        ]
    }
    ```
    """
    def __init__(self, usersJsonFile):
        self.usersJsonFile = usersJsonFile

    def connect(self):
        path = self.usersJsonFile
        timestamp = os.path.getmtime(path)
        with open(path) as json_file:
            users = json.load(json_file).get('users', [])
            return users, timestamp

    def authenticate(self, username, password, info):
        if info is None:
            return None
        if password \
            and bcrypt.checkpw(
                password.utf8,
                info.get('password', '').encode('utf-8')):
            # All users are defined in advance through the file.
            # Thus, do not supply user information in return.
            return {}
        else:
            return None


