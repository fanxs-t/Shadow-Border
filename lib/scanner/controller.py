#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import queue as Queue
import threading
import lib.common as common
from lib.common import logger
from lib.redisopt import redisCli as redis
from lib.scanner.request import Request
from lib.scanner.data import th, poc_result, scanner
from lib.scanner.engine import engine
from lib.scanner.task import TaskManager, Task
from lib.scanner.result import result_parser
from time import sleep


def request_producer():
    logger.success("Initialize the Request Producer.")
    while common.scanner_status:
        # get task from redis
        request = redis.get_request()
        if request is None:
            sleep(1)
            continue
        # parse request from task
        request_obj = Request(request)
        # filter
        if filter_request(request_obj) == "filtered":
            redis.delete_request(request_obj.id)
            continue
        # task
        new_task = Task(request_obj)
        scanner.task_manager.add(new_task, True)


def filter_request(request_obj):
    black_extension = common.conf["black_ext"].split(",")
    black_domain = common.conf["black_domain"].split(",")
    white_domain = common.conf["white_domain"].split(",")

    # host is not in blacklist & in whitelist
    host = request_obj.host
    if any(white_domain):
        if host not in white_domain:
            logger.info("Request Filtered.Host %s not in the whitelist" % host)
            return "filtered"
    else:
        if host in black_domain:
            logger.info("Request Filtered.Host %s in the blacklist" % host)
            return "filtered"

    # filename extension not in black_extension
    path = request_obj.path
    ending = path[path.rfind("/"):]
    if ending.find(".") >= 0:
        ext = ending[ending.rindex(".") + 1:]
        if ext in black_extension:
            logger.info("Request Filtered.Filename Extension %s in the blacklist" % ext)
            return "filtered"
    return True


class Controller(object):
    def __init__(self):
        if not common.scanner_status:
            logger.warning("Controller Initialization Stopped due to halted scanning status.")
            self.run = bool                    # Just use arbitrary function to replace 'run'
            return None
        info_msg = 'Initialize controller...'
        logger.success(info_msg)
        scanner.task_manager = TaskManager()
        th.queue = Queue.Queue()
        poc_result.queue = Queue.Queue()
        self.precheck_list()

    @staticmethod
    def precheck_list():
        # remove items that are not in "request"
        def _existance_check(listname):
            list_len = redis.conn.llen(listname)
            if list_len > 0:
                for i in range(0, list_len, 1):
                    request_id = redis.conn.lindex(listname, i)
                    if redis.retrieve_request(request_id) is None:
                        redis.conn.lrem(listname, 0, request_id)

        _existance_check("waiting")
        _existance_check("running")

        # pre-process the running list
        # move items from "running" to "waiting" if the item is beyond the tasks limitation index
        threshold = scanner.task_manager.tasks_limitation
        running_list_len = redis.conn.llen("running")
        if running_list_len == 0:
            return
        for request_id in redis.conn.lrange("running", 0, threshold - 1):
            request = redis.retrieve_request(request_id)
            request_obj = Request(request)
            new_task = Task(request_obj)
            scanner.task_manager.add(new_task, False)
        if running_list_len > threshold:
            for request_id in redis.conn.lrange("running", threshold, running_list_len):
                redis.conn.lpush("waiting", request_id)
            redis.conn.ltrim("running", 0, threshold - 1)
        logger.success("Finish Pre-check.")

    def run(self):
        target_thread = threading.Thread(target=request_producer, args=())
        engine_thread = threading.Thread(target=engine, args=())
        result_thread = threading.Thread(target=result_parser, args=())
        # start working
        target_thread.setDaemon(True)
        engine_thread.setDaemon(True)
        result_thread.setDaemon(True)
        target_thread.start()
        engine_thread.start()
        result_thread.start()
        # join
        target_thread.join()
        engine_thread.join()
        result_thread.join()

