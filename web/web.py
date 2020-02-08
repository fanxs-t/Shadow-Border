#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import os
import site  # Add the boilerplate's directories to Python's site-packages path.
import tornado.web
import tornado.ioloop
from tornado.options import define, options
from lib.common import logger
from conf.settings import RUNNING_PATH
from web.urls import url_patterns
import lib.common as common
import logging


def make_app(settings):
    return tornado.web.Application(url_patterns, **settings)


def web_init():
    # 这里做的就是 把web服务建立起来
    define("port", default=int(common.conf["port"]), type=int)
    define("address", default=common.conf["ip"])
    tornado.options.parse_command_line()
    path = lambda root, *a: os.path.join(root, *a)

    # WEB 应用设置
    settings = {}
    settings['static_path'] = path(RUNNING_PATH, "web", "static")
    settings['template_loader'] = tornado.template.Loader(path(RUNNING_PATH, "web", "templates"))
    settings['login_url'] = "/login"
    settings['debug'] = False
    site.addsitedir(path(RUNNING_PATH, 'handlers'))

    # 开启WEB服务
    app = make_app(settings)
    app.listen(port=options.port, address=options.address)
    logger.success("Web app start at: http://%s:%s" % (options.address, options.port))
    # Tornado WEB服务开始工作
    tornado.ioloop.IOLoop.current().start()
    logging.getLogger("tornado.application").disabled = True
    logging.getLogger("tornado.general").disabled = True
    logging.getLogger("tornado").disabled = True
