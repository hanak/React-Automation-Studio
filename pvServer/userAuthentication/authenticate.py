import jwt
import json
import re
import random
import string
import os
import bcrypt

import log
import pvAccess
import userAuth


class SecretString:
    """Secret string which will not dump to string implicitly.
    """
    def __init__(self, string):
        self._string = string

    @property
    def string(self):
        return self._string

    @property
    def utf8(self):
        return self._string.encode('utf8')\
            if self._string is not None else b''


def mask_left(s, unmasked_len=3, min_masked=4):
    if s is None:
        return None
    s_len = len(s)
    if s_len < min_masked:
        return '*' * min_masked
    unmasked_len = min(unmasked_len, s_len - min_masked)
    return s[:unmasked_len] + '*' * (s_len - unmasked_len)


def mask_right(s, unmasked_len=3, min_masked=4):
    if s is None:
        return None
    s_len = len(s)
    if s_len < min_masked:
        return '*' * min_masked
    unmasked_len = min(unmasked_len, s_len - min_masked)
    return '*' * (s_len - unmasked_len) + s[-unmasked_len:]


def mask_email(email):
    if email is None:
        return None
    name_domain = email.split('@')
    name_domain[0] = mask_left(name_domain[0])
    if len(name_domain) < 2:
        return name_domain[0]
    domain_components = name_domain[1].split('.')
    domain_components_last = domain_components[-1]
    domain_components[:] = ['*' * len(c) for c in domain_components]
    domain_components[-1] = mask_right(domain_components_last)
    name_domain[1] = '.'.join(domain_components)
    return '@'.join(name_domain[:2])


users=None
access=None


def AutheriseUserAndPermissions(JWT,pvname):
    global users
    try:
        username = users.find_authorized(JWT)
        if username is not None:
            permissions=access.checkPermissions(pvname,username)
            d={'userAuthorised':True,'permissions':permissions}
            return d
    except:
        log.exception('Unexpected exception in AutheriseUserAndPermissions. Denying authorization.')
    return {'userAuthorised':False}


def  AuthoriseUser(JWT):
    global users
    global access
    try:
        username = users.find_authorized(JWT)
        if username is not None:
            roles=access.checkUserRole(username)
            return {'authorised':True,'username':username,'roles':roles}
    except:
        log.exception('Unexpected exception in AuthoriseUser. Denying authorization.')
    return {'authorised':False}


def AuthenticateUser(user):
    global users
    global access
    if users is None:
        return None
    try:
        username = user.get('email', None)
        jwtId = users.authenticate(
            username,
            SecretString(user.get('password', '')))
        if jwtId is not None:
            roles = access.checkUserRole(username)
            return {'JWT':jwtId,'username':username,'roles':roles}
        else:
            log.warning('Unknown user or invalid password: "{}"', mask_email(username))
            return None
    except:
        log.exception('Unexpected exception in AuthoriseUser. Denying authentication.')
        return None


def AuthenticateInit(disabled=True, authenticator=None):
    global users
    global access
    if disabled:
        users = None
        access = None
    else:
        access=pvAccess.init(
            'userAuthentication/users/pvAccess.json')
        users=userAuth.init(
            access.timestamp,
            'userAuthentication/users/SECRET_PWD_KEY',
            'userAuthentication/users/users.json',
            authenticator)
