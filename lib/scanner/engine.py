#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import threading
import time
import traceback
import gevent
from lib.common import logger
import lib.common as common
from lib.scanner.data import th, poc_result
from gevent import monkey
monkey.patch_all()

def init_engine():
    th.threads_num = int(common.conf["threads_num"])
    th.scan_count = th.found_count = 0
    th.start_time = time.time()
    msg = 'Initialize the Engine.'
    logger.success(msg)


def scan():
    while common.scanner_status:
        if th.queue.qsize() > 0:
            task = th.queue.get(timeout=1.0)
        else:
            gevent.sleep(1)
            continue
        try:
            # POC在执行时报错如果不被处理，线程框架会停止并退出
            module, request = task[0], task[1]
            module_info = module.poc_info
            module_name = module.__name__
            logger.info("Start poc: %s at %s" % (module_name, request.url))
            scan_result = module.poc(request)
            logger.success("Finish poc: %s at %s" % (module_name, request.url))
            poc_result.queue.put([request, module_name, module_info, scan_result])
        except Exception as e:
            th.errmsg = traceback.format_exc()
            logger.error(str(e))


def engine():
    init_engine()
    while common.scanner_status:
        if th.queue.qsize() > 0:
            gevent.joinall([gevent.spawn(scan) for i in range(0, th.threads_num)])
        else:
            gevent.sleep(3)

'''
def printMessage(msg):
    dataToStdout('\r' + msg + ' ' * (th.console_width - len(msg)) + '\n\r')


def printProgress():
    msg = '%s found | %s remaining | %s scanned in %.2f seconds' % (
        th.found_count, th.queue.qsize(), th.scan_count, time.time() - th.start_time)
    out = '\r' + ' ' * (th.console_width - len(msg)) + msg
    dataToStdout(out)


def output2file(msg):
    if th.thread_mode: th.file_lock.acquire()
    f = open(th.output, 'a')
    f.write(msg + '\n')
    f.close()
    if th.thread_mode: th.file_lock.release()
'''