#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border
# author = Fanxs


from web.web import web_init
from lib.init import init

VERSION = "1.0"
logo = """
         _______   ____ _               _               
       ________  / ____| |             | |        
 _____________  | (___ | |__   __ _  __| | _____      __  
       _______   \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /    Version %s.%s  
           ____  ____) | | | | (_| | (_| | (_) \_V _V /__  ___  _______   
      ________  |_____/|_| |_|\__,_|\__,_|/ _ )/ __ \/ _ \/ _ \/ __/ _ \ 
            __________________________   / _  / /_/ / , _/ // / _// , _/ 
                    ________________    /____/\____/_/|_/____/___/_/|_|  
""" % tuple(VERSION.split('.'))

if __name__ == '__main__':
    print(logo)
    init()
    web_init()
