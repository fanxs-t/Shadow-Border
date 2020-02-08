#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


from web.handlers import main

# 路由表
url_patterns =  [
    (r"^/$", main.IndexHandler),
    (r"^/login", main.LoginHandler),
    (r"^/logout", main.LogoutHandler),
    (r"^/index", main.IndexHandler),
    (r"^/config", main.ConfHandler),
    (r"^/scan_config", main.ScanConfigHandler),
    (r"^/scan_stat", main.ScanStatHandler),
    (r"^/req", main.ReqHandler),
    (r"^/bug", main.BugHandler),
    (r"^/list", main.ListHandler),
    (r"^/del", main.DelHandler),
    (r"^/.*", main.PageNotFoundHandler),
]


