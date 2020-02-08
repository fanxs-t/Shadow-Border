#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import os
import time
from hashlib import md5
from conf.settings import SESSION_CONF_FILE
import lib.common as common

'''
Create session string or update web session into session file.
Control the length of session file to make sure it will not be too big.
Destroy web session string to make it logout.
'''


def new(ip):
    md = md5()
    md.update((common.conf["cookie_secret"] + str(time.time()) + ip).encode('utf-8'))
    return md.hexdigest()


def check(session):
    with open(SESSION_CONF_FILE, 'r+') as f:
        lines = f.readlines()
        f.close()
        for line in lines:
            if session == line.strip():
                return True
        return False


def update(session):
    size_control()
    with open(SESSION_CONF_FILE, 'a') as f:
        f.write(session + '\n')
        f.close()
        return True


def destroy(session):
    with open(SESSION_CONF_FILE, 'r') as f:
        lines = f.readlines()
        f.close()
        ff = open(SESSION_CONF_FILE, 'w')
        for line in lines:
            if session != line.strip():
                ff.write(line)
        ff.close()
        return True


def size_control():
    if os.path.getsize(SESSION_CONF_FILE) > int(common.conf["session_size"]):
        with open(SESSION_CONF_FILE, 'r') as f:
            lines = f.readlines()
            f.close()
            ff = open(SESSION_CONF_FILE, 'w')
            size = 0
            for line in lines:
                size += len(line)
                if size < common.conf["session_size"]:
                    ff.write(line)
                else:
                    ff.close()
                    return
            ff.close()
