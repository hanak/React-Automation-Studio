import os
import re
import json

import log


class PvAccess:
    """Access control to PV variables.
    """
    def __init__(self, pvAccessJsonFile=None):
        self.timestamp = '0'
        self.userGroups = {}
        self.pvAccessJsonFile = pvAccessJsonFile

    def connect(self):
        if self.pvAccessJsonFile is not None:
            try:
                timestamp = os.path.getmtime(self.pvAccessJsonFile)
                with open(self.pvAccessJsonFile) as json_file:
                    self.loadDict(json.load(json_file), timestamp)
            except:
                log.exception(
                    'Exception while loading pvAccess.json. No data loaded.')

    def loadDict(self, data, timestamp):
        self.timestamp = str(timestamp)
        self.userGroups = data.get('userGroups', {})

    def checkPermissions(self, pvname, username):
        d = {'read': False, 'write': False, 'roles': []}
        if pvname is None:
            return d

        roles = {}
        pvname = str(pvname)
        for uag, group in self.userGroups.items():
            for groupUsername in group.get('usernames', []):
                if (username == groupUsername) or (groupUsername == "*"):
                    for rules in group['rules']:
                        match = re.search(str(rules['rule']), pvname)
                        if match:
                            d['read'] = rules['read']
                            d['write'] = rules['write']
                    for role in group.get('roles', []):
                        if role:
                            roles[role] = True
        d['roles'] = [k for k in roles.keys()]
        return d

    def checkUserRole(self, username):
        roles = {}
        for uag, group in self.userGroups.items():
            for groupUsername in group.get('usernames', []):
                if (username == groupUsername) or (groupUsername == "*"):
                    for role in group.get('roles', []):
                        if role:
                            roles[role] = True
        return [k for k in roles.keys()]


def init(pvAccessJsonFile):
    instance = PvAccess(pvAccessJsonFile)
    instance.connect()
    return instance
