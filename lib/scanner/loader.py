#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import importlib.util as imp
import sys
from conf.settings import ESSENTIAL_MODULE_METHODS, ESSENTIAL_VALUABLES, ESSENTIAL_POC_INFO
from conf.settings import SCRIPT_PATH
from lib.common import used_pocs, logger
from lib.scanner.data import scanner
import os.path
import lib.common as common


def load_modules():
    _path = SCRIPT_PATH
    scanner.module_obj = []
    if not used_pocs:
        msg = "No Poc scripts are loaded. Scanner Stopped."
        logger.error(msg)
        common.scanner_status = False
    for _name in used_pocs:
        __name = "script." + _name
        _load_module(__name, os.path.join(_path, _name) + ".py")


def _load_module(_name, _path):
    msg = 'Load custom script: %s at %s' % (_name, _path)
    logger.success(msg)

    try:
        spec = imp.find_spec(_name, [_path])
        module = imp.module_from_spec(spec)
        spec.loader.exec_module(module)
        module_check(module)
        scanner.module_obj.append(module)
    except ImportError as e:
        error_msg = "Fail to import [%s.py] at %s\n%s" \
                   % (_name, _path, '[Error Msg]: ' + str(e))
        sys.exit(logger.error(error_msg))
    except AttributeError as e:
        error_msg = "Fail to find [%s.py] at %s\n%s" \
                   % (_name, _path, '[Error Msg]: ' + str(e))
        sys.exit(logger.error(error_msg))


'''
    Ensure all imported modules have the essential information defined.
'''


def module_check(module):
    for each in ESSENTIAL_MODULE_METHODS:
        if not hasattr(module, each):
            errorMsg = "Can't find essential method:'%s()' in %s script，Please modify your script/PoC." % (
            each, module.__name__)
            sys.exit(logger.error(errorMsg))
    for each in ESSENTIAL_POC_INFO:
        if not hasattr(module, each):
            errorMsg = "Can't find essential valuables:'%s' in %s script，Please modify your script/PoC." % (
            each, module.__name__)
            sys.exit(logger.error(errorMsg))
    # basic info must be defined :
    # module.poc_info, module.poc_info["poc"], module.poc_info["vul"],
    # module.poc_info["poc"]["Name"], module.poc_info["vul"]["Product"], module.poc_info["vul"]["Severity"]
    try:
        for each in ESSENTIAL_VALUABLES:
            eval("module.%s" % each)
    except Exception:
        errorMsg = "Can't find essential valuables:'%s' in %s script，Please modify your script/PoC." % (
        each, module.__name__)
        sys.exit(logger.error(errorMsg))
    return True


if __name__ == "__main__":
    used_pocs = ["sql_injection_detection", "xss_detection"]
    import script.sql_injection_detection as sql

    file_name = sql.__file__
    module_name = sql.__name__
    print("Module: " + module_name)
    print("PATH: " + file_name)
    load_modules()
