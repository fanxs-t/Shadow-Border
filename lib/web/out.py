#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border


def jump(url):
    return "<script>window.location.href=\"%s\"</script>" % url

def alert(content, url):
    return "<script>window.location.href=\"%s\";alert(\"%s\");</script>" % (url, content)
