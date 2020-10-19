class Authenticator:
    """User authentication engine base class.
    """
    def connect(self):
        """Connect to the authentication source.

        Returns
        -------
        tuple (users, code)
            Result containing:
            users : list
                List of user information which is pre-loaded.
                Each record is a dictionary with a mandatory
                key username.
            code : str
                Salt-like string which is used to build JWT.
                If it differs between startup, it will make
                all issued JWT invalid.
        """
        return ([], None)

    def authenticate(self, username, password, info):
        """Authenticate a user.

        Parameters
        ----------
        username : str
            Username or login.
            This field may contain personally identifyable information such as email.
        password : SecretString
            Plain-text password.
            Use properties string or uft8 to access the pasword.
        info : dict
            Cached information associated with the username.
            The info was either pre-loaded (see function load())
            or generated during login process (see return value).

        Returns
        -------
        None or dict
            Return None if the user was not authorized.
            Return dictionary if the user was authorized.
            If the parameter info is None,
            the dictionary will be will be cached. At minimum
            the dictionary should include a key username containing
            the username.
        """
        return None
