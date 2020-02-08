#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import logging
import sys
from conf.settings import LOG_PATH
import os.path
import time

from lib.core.enums import CUSTOM_LOGGING

logging.addLevelName(CUSTOM_LOGGING.SYSINFO, "*")
logging.addLevelName(CUSTOM_LOGGING.SUCCESS, "+")
logging.addLevelName(CUSTOM_LOGGING.ERROR, "-")
logging.addLevelName(CUSTOM_LOGGING.WARNING, "!")

LOGGER = logging.getLogger("logger")
FILENAME_APPENDIX = time.strftime("%Y%m%d%H%M%S",time.localtime(int(time.time())))
FILE_HANDLER = logging.FileHandler(os.path.join(LOG_PATH, "logs-%s.txt"%FILENAME_APPENDIX))
LOGGER_HANDLER = None

try:
    from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

    try:
        LOGGER_HANDLER = ColorizingStreamHandler(sys.stdout)
        LOGGER_HANDLER.level_map[logging.getLevelName("*")] = (None, "cyan", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("+")] = (None, "green", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("-")] = (None, "red", False)
        LOGGER_HANDLER.level_map[logging.getLevelName("!")] = (None, "yellow", False)
    except Exception as e:
        LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

except ImportError as e:
    LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

FORMATTER = logging.Formatter("\r[%(levelname)s %(asctime)s] %(message)s", "%y%m%d %H:%M:%S")


LOGGER_HANDLER.setFormatter(FORMATTER)
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.propagate = False
LOGGER.addHandler(FILE_HANDLER)
LOGGER.setLevel(CUSTOM_LOGGING.WARNING)


class MY_LOGGER:
    @staticmethod
    def success(msg):
        return LOGGER.log(CUSTOM_LOGGING.SUCCESS, msg)

    @staticmethod
    def info(msg):
        return LOGGER.log(CUSTOM_LOGGING.SYSINFO, msg)

    @staticmethod
    def warning(msg):
        return LOGGER.log(CUSTOM_LOGGING.WARNING, msg)

    @staticmethod
    def error(msg):
        return LOGGER.log(CUSTOM_LOGGING.ERROR, msg)
