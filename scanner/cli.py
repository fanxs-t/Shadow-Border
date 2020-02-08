#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import traceback
from lib.scanner.loader import load_modules
from lib.common import logger
from lib.scanner.controller import Controller
from lib.scanner.data import scanner


def create_scanner():
    """
        Main function of POC-T when running from command line.
    """
    try:
        load_modules()
        scanner.controller = Controller()
        scanner.controller.run()
    except Exception:
        print(traceback.format_exc())
        logger.error("Error in initializing the controller.")

