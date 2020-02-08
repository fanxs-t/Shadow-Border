#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import json

class Request(object):
    def __init__(self, request):
        self.path = ""
        self.query = ""
        self.headers = ""
        self.method = ""
        self.host = ""
        self.port = ""
        self.url = ""
        self.body = ""
        self.raw = ""
        self.protocol = ""
        # the hash of request
        self.id = request[0].decode()
        self.initialize(request[1])

    def initialize(self, request):
        request = json.loads(request)
        self.path = request["path"]
        self.query = request["query"]
        self.headers = request["headers"]
        self.body = request["postdata"]
        self.host = request["host"]
        self.port = request["port"]
        self.method = request["method"]
        self.protocol = request["protocol"]
        self.url = self.protocol + "://" + self.host + ":" + self.port + self.path + ('?' + self.query if self.query != "" else "")
        self.raw = request["requestRaw"]
        return None

if __name__ == '__main__':
    from lib.redisopt import redisCli
    from lib.config import load_config
    load_config()
    redisCli.build_connection()
    r = Request(redisCli.get_request())
    print(r.protocol, r.host, r.path,  r.query, r.headers, r.body, r.host, r.method, r.url, r.id)
    print(list(map(type, [r.host, r.path, r.query, r.headers, r.body, r.host, r.method, r.url, r.id])))

