#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import os
from lib.redisopt import redisCli as redis
from lib.common import logger
import lib.common as common
from conf.settings import SCRIPT_PATH
from conf.settings import DEFAULT_POCS_PATH
import sys
from lib.config import load_config
import json


def init():
    version_check()
    check_requirements()
    load_config()
    redis_connection_check()
    poc_reset()


def redis_connection_check():
    try:
        redis.build_connection()
    except Exception as e:
        msg = "Fail to build connection with Redis. Please modify the configure file, check the redis status and " \
              "restart. "
        logger.error(msg)
        return False
    else:
        logger.success("Build connection with redis")
        return True


def retrieve_default_pocs():
    with open(DEFAULT_POCS_PATH, 'r') as fh:
        settings = json.loads(fh.read())
        for p in common.all_pocs:
            if p in settings.keys() and settings[p] == "True":
                common.used_pocs.append(p)


def poc_reset():
    pocs = []
    for p in os.listdir(SCRIPT_PATH):
        if p.startswith("__"):
            continue
        else:
            pocs.append(p.replace(".py", ""))
    common.all_pocs = pocs
    retrieve_default_pocs()


def version_check():
    PYVERSION = sys.version.split()[0]
    if PYVERSION <= "3.4":
        msg = '''[CRITICAL] incompatible Python version detected ('%s'). 
        For successfully running this project, you'll have to use version > 3.4.(visit 'http://www.python.org/download/')''' % PYVERSION
        logger.error(msg)
        common.scanner_status = False


def check_requirements():
    try:
        import tornado
        import redis
        import gevent
        import treelib
        import requests
    except ImportError as e:
        logger.error("Fail to import required libray."+str(e))
        exit(0)
