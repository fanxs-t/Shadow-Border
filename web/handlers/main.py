#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import json
import base64
import urllib.parse as urllib
import tornado.web
from lib.config import update_config
from lib.redisopt import redisCli as redis
from lib.common import logger
from lib import secure
from lib.web import session
import lib.common as common
from lib.web import out
from web.handlers.base import BaseHandler, authenticated
from scanner.cli import create_scanner
import threading
from conf.settings import DEFAULT_CONF_FILE, DEFAULT_POCS_PATH, CHECK_CONF_FILE


class PageNotFoundHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("404.html")


# 登出
class LogoutHandler(BaseHandler):

    @authenticated
    def get(self):
        session.destroy(self.get_cookie("token"))
        self.set_header("Location", "/")
        self.set_status(302)
        return


# 登录
class LoginHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("login.html")

    def post(self):
        account = secure.clear(self.get_argument("account"))
        password = secure.clear(self.get_argument("password"))
        if account == common.conf['account'] and password == common.conf['password']:
            cookie = session.new(self.request.remote_ip)
            self.set_cookie("token", cookie, expires_days=int(common.conf["session_expires_time"]))
            session.update(cookie)
            self.set_header("Location", "/")
            self.set_status(302)
            return
        else:
            location = "/login"
            content = "Something wrong with you account or password!"
            return self.render("302.html", location=location, content=content)


# 展示首页数据
class IndexHandler(BaseHandler):

    @authenticated
    def get(self):
        waiting = redis.conn.lrange("waiting", 0, 15)
        running = redis.conn.lrange("running", 0, 15)
        finished = redis.conn.lrange("finished", 0, 15)
        vulnerable = redis.conn.zrange("vulnerable", 0, 15)
        vulnerable_list = []
        stats = ['secure', 'low', 'medium', "high"]
        stats_all = {}
        for i in [waiting, running, finished]:
            for reqhash in i:
                stats_all[reqhash] = 'secure'

        for i in vulnerable:
            decode_results = json.loads(base64.b64decode(i))
            reqhash = decode_results["task_id"]
            severity = decode_results["vulnerability_severity"].lower()
            name = decode_results["vulnerability_name"]
            vulnerability_id = decode_results["vulnerability_id"]
            stats_all[reqhash] = severity
            vulnerable_list.append({"reqhash": reqhash, "severity": severity, "name": name, "score": vulnerability_id})

        self.render("index.html", waiting_num=redis.conn.llen("waiting"), running_num=redis.conn.llen("running"),
                    finished_num=redis.conn.llen("finished"),
                    vulnerable_num=redis.conn.zcard("vulnerable"), waiting=waiting, running=running,
                    finished=finished, vulnerable_list=vulnerable_list,
                    time=common.conf["flush_time"], stats_all=stats_all)
        return


# 基础设置
class ConfHandler(BaseHandler):

    @authenticated
    def get(self):
        if "restore" in self.request.arguments:
            try:
                with open(DEFAULT_CONF_FILE, 'r') as handler:
                    default_configuration = json.loads(handler.read())
                    update_config(default_configuration, CHECK_CONF_FILE)
            except Exception as e:
                logger.error("Fail to restore the default configuration.%s"%str(e))
                update_config(common.conf, CHECK_CONF_FILE)
            else:
                common.conf = default_configuration
                logger.success("Restored default configuration.")

        scan_methods = {"GET":"","POST":"","DELETE":"","PUT":""}
        options = common.conf["scan_methods"].split(",")
        for m in options:
            if m.upper() in scan_methods:
                scan_methods[m] = "checked"
        return self.render("config.html", config=common.conf, scan_methods=scan_methods)

    @authenticated
    def post(self):
        scan_methods = []
        conf_all = common.conf
        for i in self.request.body.decode().split("&"):
            para = secure.clear(urllib.unquote(i.split("=", 1)[0]))
            value = secure.clear(urllib.unquote(i.split("=", 1)[1]))
            if para in conf_all.keys():
                conf_all[para] = value
            elif "scan_methods" in para:
                scan_methods.append(para[para.rindex("_")+1:].upper())
        conf_all["scan_methods"] = ",".join(scan_methods)
        update_config(conf_all, CHECK_CONF_FILE)
        return self.write(out.alert("Success!","/config"))


# 扫描设置
class ScanConfigHandler(BaseHandler):

    @authenticated
    def get(self):
        applied_pocs = {}
        for _ in common.all_pocs:
            if _ in common.used_pocs:
                applied_pocs[_ + "_true"] = "checked"
                applied_pocs[_ + "_false"] = ""
            else:
                applied_pocs[_ + "_true"] = ""
                applied_pocs[_ + "_false"] = "checked"
        return self.render("scan_config.html", all_pocs=common.all_pocs, applied_pocs=applied_pocs,
                           scan_stat=common.scanner_status)

    @authenticated
    def post(self):
        if "save_default" in self.request.arguments:
            pocs_default = dict()
            for p in self.request.body_arguments:
                if self.get_argument(p) == "true":
                    pocs_default[p] = "True"
                else:
                    pocs_default[p] = "False"
            update_config(pocs_default, DEFAULT_POCS_PATH)

        for p in common.all_pocs:
            if ((self.get_argument(p) == "true") and (p not in common.used_pocs)):
                common.used_pocs.append(p)
            elif ((self.get_argument(p) == "false") and (p in common.used_pocs)):
                common.used_pocs.remove(p)
        return self.write(out.jump("/scan_config"))

# 获取请求的具体数据
class ReqHandler(BaseHandler):

    @authenticated
    def get(self):
        try:
            request_hash = self.get_argument("hash")
            request = json.loads(base64.b64decode(redis.conn.hget("request", request_hash)))
            protocol = request['protocol']
            port = request["port"]
            path = request['path']
            host = request['host']
            query = request['query']
            packet = base64.b64decode(request['requestRaw'])
            request['url_encode'] = ""
            url = protocol + "://" + host + ":" + port + path + ('?' + query if query != "" else "")
            return self.render("req.html", request=request, packet=packet, url=url)
        except Exception as e:
            logger.error(str(e))
            return self.write(str(e))

# 获得漏洞的具体数据
class BugHandler(BaseHandler):

    @authenticated
    def get(self):
        try:
            score = self.get_argument("id")
            scan_result = json.loads(base64.b64decode(redis.conn.zrangebyscore("vulnerable", score, score)[0]))
            request_hash = scan_result["task_id"]
            vulnerability_severity = scan_result["vulnerability_severity"].lower()
            vulnerability_name = scan_result["vulnerability_name"]
            url = scan_result["url"]
            vulnerability_product = scan_result["vulnerability_product"]
            vulnerability_extra_info = scan_result["vulnerability_extra_info"]
            module_name = scan_result["module_name"]

            # raw packet
            request = json.loads(base64.b64decode(redis.conn.hget("request", request_hash)))
            packet = base64.b64decode(request['requestRaw'])
            # split the url in 80 chars
            url_encode = ""
            for i in range(int(len(url) / 80) + 1):
                url_encode += url[i * 80:i * 80 + 80] + "\n"
            return self.render("bug.html", url=url, id=score, url_encode=url_encode, vulnerability_severity=vulnerability_severity, vulnerability_name=vulnerability_name,
                               vulnerability_product=vulnerability_product, vulnerability_extra_info=vulnerability_extra_info, module_name=module_name, packet=packet)
        except Exception as e:
            logger.error(str(e))
            return self.write(str(e))


# View more， 显示更多
class ListHandler(BaseHandler):

    @authenticated
    def get(self):
        list_type = self.get_argument("type")
        try:
            start = int(self.get_argument("start"))
        except:
            start = 0
        page_num = int(common.conf['page_num'])
        length = redis.conn.zcard(list_type)
        last = start + page_num - 1
        page_now = int(start / page_num + 1)
        end_page = int(-1 * ((-1 * length) / page_num))
        end_num = end_page * page_num - page_num
        if page_now - 2 >= 1:
            pages_first = page_now - 2
        else:
            pages_first = 1
        if page_now + 2 <= end_page:
            pages_last = page_now + 2
        else:
            pages_last = end_page
        pages = range(pages_first, pages_last + 1)
        vulnerabilities = redis.conn.zrange(list_type, start, last)
        req_content = []
        stats_all = {}
        for result in vulnerabilities:
            scan_result = json.loads(base64.b64decode(result))
            severity = scan_result["vulnerability_severity"].lower()
            name = scan_result["vulnerability_name"]
            vulnerability_id = scan_result["vulnerability_id"]
            url = scan_result["url"]
            stats_all[vulnerability_id] = severity
            req_content.append([vulnerability_id, severity, name, severity, url])
        return self.render("list.html", page_now=page_now, page_num=page_num, pages=pages,
                           list_type=list_type, length=length, req_content=req_content, end_num=end_num, time=common.conf["flush_time"])


# 删除waiting,finished,running,vulnerable中的项目
# 或清空redis
class DelHandler(BaseHandler):

    @authenticated
    def get(self):
        del_type = self.get_argument("type")
        if del_type in ['waiting', 'finished', 'running', 'vulnerable']:
            redis.conn.delete(del_type)
            return self.write(out.jump("/"))
        elif del_type == "flushdb":
            redis.conn.delete("waiting")
            redis.conn.delete("finished")
            redis.conn.delete("running")
            redis.conn.delete("vulnerable")
            redis.conn.delete("request")
            common.scanner_status = False
            logger.info("Clear all db data and stop the scanner.")
            return self.write(out.alert("Clear all db data and Stop the scanner.", "/"))
        elif del_type == "singlebug":
            id = self.get_argument("id")
            redis.conn.zremrangebyscore("vulnerable", id, id)
            logger.info("Delete a bug %s"%id)
            return self.write(out.jump("/list?type=vulnerable"))


# 获取和更新扫描器状态
class ScanStatHandler(BaseHandler):

    @authenticated
    def get(self):
        stat = secure.clear(self.get_argument("stat"))
        if stat == "False":
            common.scanner_status = False
            logger.success("Stop the scanner.")
        else:
            common.scanner_status= True
            # start scanning
            logger.success("Start the scanner.")
            thread = threading.Thread(target=create_scanner, args=())
            thread.setDaemon(True)
            thread.start()
            logger.success("Start the scanner.")

        return self.write(out.jump("/scan_config"))