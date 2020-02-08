#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


from lib.common import logger
from lib.redisopt import redisCli as redis
from lib.scanner.data import th, scanner
from time import sleep

class TaskManager(object):
    def __init__(self):
        self.tasks_limitation = 16
        self.tasks = {}
        self.running_task_num = 0

    def add(self, task, modify_redis):
        if task.id in self.tasks.keys():
            logger.info("Duplicate task received:%s" % task.id)
            return False
        else:
            while self.running_task_num >= self.tasks_limitation:
                sleep(1)
            logger.success("Add new task into the TaskManager %s" % task.id)
            self.tasks[task.id] = task
            task.scan()
            self.running_task_num += 1
            # move request id from waiting to running
            if modify_redis:
                redis.run_task(task.id)

    def update(self, task_id, module_name, status):
        task = self.tasks[task_id]
        task.update(module_name, status)
        if task.finished():
            logger.info("Finish Task with id %s" % task_id)
            self.remove(task_id)

    def remove(self, task_id):
        redis.remove_task(task_id)
        self.running_task_num -= 1

class Task(object):
    def __init__(self, request):
        self.id = request.id
        self.status = {}
        self.started = False
        self.request = request
        for m in scanner.module_obj:
            module_name = m.__name__
            self.status[module_name] = False
        logger.info("New task %s." % self.id)
        self.url = request.url

    # return if all tasks are finished
    def finished(self):
        return all(self.status.values())

    def update(self, module_name, status):
        self.status[module_name] = status
        logger.info("Update task %s scanning status: %s, %s."%(self.id, module_name, status))
        return True

    def scan(self):
        for module in scanner.module_obj:
            th.queue.put([module, self.request])
        logger.success("Adding new scan for %s"%self.url)

if __name__=="__main__":
    from lib.scanner.request import Request
    from lib.scanner.loader import load_modules
    load_modules()
    redis.build_connection()
    request = redis.get_request()
    # parse request from task
    request_obj = Request(request)
    new_task = Task(request_obj)
    print(new_task.id, new_task.status, new_task.url)