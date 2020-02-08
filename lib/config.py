#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import warnings
import json
from conf.settings import CHECK_CONF_FILE
import lib.common as common
from lib.common import logger

warnings.filterwarnings("ignore")


def load_config():
    with open(CHECK_CONF_FILE) as con:
        try:
            common.conf = json.load(con)
            return True
        except:
            logger.error("conf.json error, please download another one and replace it.")
            exit()


def update_config(conf, path):
    with open(path, 'w') as con:
        content = json.dumps(conf).replace("{", "{\n").replace("}", "\n}").replace(", ", ",\n").replace("'", '"')
        con.write(content)
    logger.success("Update the configuration %s"%path)
    load_config()
    return


