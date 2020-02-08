#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


from lib.redisopt import redisCli as redis
from lib.scanner.data import poc_result, scanner
import lib.common as common
from lib.common import logger
import base64
import time
import json

class ResultParser(object):
    def __init__(self):
        self.output_setting = []
        self.output_csv = False
        self.output_csv_file = ""

    def redis_record(self, task_id, vulnerability_severity, vulnerability_name, url, vulnerability_product, vulnerability_extra_info, module_name):
        score = 0
        if vulnerability_severity == "HIGH":
            score = 10000000000
        elif vulnerability_severity == "MEDIUM":
            score = 50000000000
        elif vulnerability_severity == "LOW":
            score = 90000000000
        score += time.time()
        vulnerability_json = {"task_id": task_id,
                              "vulnerability_severity": vulnerability_severity,
                              "vulnerability_name": vulnerability_name,
                              "url": url,
                              "vulnerability_product": vulnerability_product,
                              "vulnerability_extra_info": vulnerability_extra_info,
                              "module_name": module_name,
                              "vulnerability_id": score
                              }
        base64_vulnerability = base64.b64encode(json.dumps(vulnerability_json).encode())
        redis.recode_bug(score, base64_vulnerability)

    def csv_record(self, info):
        None

    def parse(self, result):
        request, module_name, module_info, scan_result = result[0], result[1], result[2], result[3]
        scanner.task_manager.update(request.id, module_name, "FINISHED")
        if scan_result["Success"]:
            self.process_vulnerability(request, module_name, module_info, scan_result)
        if scan_result["Error"]:
            msg = 'Error in Executing the %s poc for URL %s. Error Message is %s' %(module_name, request.url, scan_result["Error"])
            logger.error(msg)

    def process_vulnerability(self, request, module_name, module_info, scan_result):
        id = request.id
        url = request.url
        raw_request = request.raw
        poc_details = module_info["poc"]
        vul_info = module_info["vul"]
        vulnerability_name = poc_details["Name"]
        vulnerability_product = vul_info["Product"]
        vulnerability_severity = vul_info["Severity"].strip().upper()
        vulnerability_extra_info = ""
        try:
            vulnerability_extra_info = scan_result["Ret"]
        except Exception:
            pass
        self.redis_record(id, vulnerability_severity, vulnerability_name, url, vulnerability_product,
                          vulnerability_extra_info, module_name)
        if self.output_csv:
            self.csv_record([vulnerability_severity, vulnerability_name, url, vulnerability_product,
                             vulnerability_extra_info, raw_request, module_name])
        msg = 'Disclose a vulnerability %s at %s' % (vulnerability_name, url)
        logger.success(msg)

def result_parser():
    parser = ResultParser()
    logger.success("Initialize the Result Parser.")
    while common.scanner_status:
        if poc_result.queue.qsize() > 0:
            result = poc_result.queue.get(timeout=1.0)
            parser.parse(result)
        else:
            time.sleep(2)

if __name__ == "__main__":
    from lib.scanner.request import Request
    redis.build_connection()
    parser = ResultParser()
    request = ["b400d3e5ff8397ca0c372396bdd7a2a8", json.dumps({"url": "teshwh", "requestRaw": "testraw", "query":"1", "path":"test54444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444dwadwadwwdwwd", "headers":"empty", "postdata":"", "host": "www.baidu.com", "method": "GET"})]
    request = Request(request)
    module_name = "script.test"
    module_info = {
        'poc': {
            'Id': '',  # poc编号
            'Name': 'SQL Injection',  # poc名称
            'Author': 'winkar',  # poc作者
            'Create_date': '2015-01-27',  # poc创建时间：如'2014-11-19'
        },
        'vul': {
            'Product': 'Ewebeditor',  # 漏洞所在产品名称
            'Version': '',  # 产品的版本号
            'Type': 'Database Found',  # 漏洞类型
            'Severity': 'medium',
            'isWeb': True,
            'Description': '''
	       	    ewebeditor默认情况下， 其数据库可直接下载，从而导致攻击者可据此信息进行后续攻击。

	       	    example:
	       	    http://www.cn-yuehua.com/admin/ewebeditor/db/ewebeditor.mdb
	        ''',
            'DisclosureDate': '',  # poc公布时间：如'2014-11-19'
        }
    }
    scan_result = {
        'Error': False,  # 记录poc失败信息，若未报错则为False
        'Success': True,  # 是否执行成功，默认值为False表示poc执行不成功，若成功请更新该值为True
        'Ret': "TEST!"  # 记录额外的poc相关信息
    }
    result = [request, module_name, module_info, scan_result]
    parser.parse(result)
    print(redis.conn.zcount("vulnerable",0,10))
