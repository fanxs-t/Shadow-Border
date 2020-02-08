#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


from redis import StrictRedis
import base64
from lib.common import logger
import lib.common as common

'''
Connect redis and excute the command of redis from other class
Deal with packet insert things
'''

class RedisCli(object):

    def __init__(self):
        self.conn = None

    def build_connection(self):
        workerconf = common.conf
        redisconf = dict()
        redisconf['host'] = workerconf["redis_host"]
        redisconf['password'] = workerconf['redis_pass']
        redisconf['port'] = workerconf['redis_port']
        self.conn = StrictRedis(**redisconf)

    def remove_task(self, task_id):
        # move task from running to finished
        self.conn.lrem("running", 1, task_id)
        self.conn.lpush("finished", task_id)

    def run_task(self, task_id):
        # move task from waiting to running
        # task is removed from waiting list by blpop
        self.conn.lpush("running", task_id)

    def recode_bug(self, score, base64_vulnerability):
        # add disclosed vulnerabilities into 'vulnerable' list
        self.conn.zadd("vulnerable", {base64_vulnerability:score})

    def get_request(self):
        _request_id = self.conn.blpop("waiting", 10)
        if _request_id and _request_id[0] == b"waiting":
            request_id = _request_id[1]
        else:
            return None
        result = self.retrieve_request(request_id)
        logger.success("Retrieve one request from 'waiting'.")
        return result

    def retrieve_request(self, request_id):
        _request = self.conn.hget("request", request_id)
        try:
            request = base64.b64decode(_request)
            request_decoded = request.decode("utf8", "ignore")
        except Exception as e:
            logger.error("Error in decoding the request or getting the request : %s"%request_id)
            return None
        else:
            return [request_id, request_decoded]

    def delete_request(self, request_id):
        self.conn.hdel("request", request_id)
        return None

redisCli = RedisCli()

if __name__ =="__main__":
    redisCli.build_connection()
    print(redisCli.get_request())