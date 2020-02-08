#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/fanxs-t/Shadow-Border
# author = Fanxs


import json
from treelib import Tree, Node

'''
    Designed for parse json string, especially for the case where there are jsons in a json body.
    Example:
       post_data = '{"test": "123", "test1": {"test2": "456"}}'
       ob = JsonParser(post_data)
       print(ob["test"], ob["test1"], ob["test2"])
       ob2 = ob.copy()
       ob2["test2"] = payload
       requests.request("POST", "https://www.baidu.com", json = ob2.json)
       
    Only the data of leaf nodes are allowed for data modification, the "test" and "test2" in this case.
    - JsonParser(string).json returns parse dictionary (which can be used for making requests with 'requests')
    - JsonParser(string).args returns all arguments allowed for data manipulation.
    - JsonParser(string).copy to copy this object
    - JsonParser(string)[key] to get/modify the data in the parsed json
'''
class JsonParser(object):
    def __init__(self, string):
        self.string = string
        self.is_json = False
        self.json = self._parse_json(string)
        self._args = {}
        self.tree = None
        if self.is_json:
            self.tree = self._dict_to_tree(self.json)
            self._get_leaves()
        else:
            self.json = None

    def keys(self):
        '''
        Return all keys of the parsed json.
        :return: json.keys()
        '''
        return self.json.keys() if self.is_json else []

    def args(self):
        '''
        Return the list of leaf nodes that are allowed for manipulation.
        :return: list
        '''
        return list(self._args.keys())

    def __getitem__(self, item):
        if item in self._args:
            identifier = self._args[item]
            return self.tree.nodes[identifier].data
        elif item in self.json:
            return self.json[item]
        else:
            raise KeyError

    def __setitem__(self, key, value):
        if key in self._args:
            identifier = self._args[key]
            self.tree.nodes[identifier].data = value
            self.json = self._tree_to_dict(self.tree)
        else:
            raise Exception("Cannot modify data of non-leaf nodes. You can only modify the data in the args()")

    def copy(self):
        '''
        Deep copy the object
        :return: JsonParser
        '''
        return JsonParser(self.string)

    def _parse_json(self, s):
        '''
        Parse json string to dict. Designed for handling the case where there is json in a json.
        :param s: json string
        :return:  dict
        '''
        try:
            jo = json.loads(s)
            if type(jo) is not dict:
                raise Exception
        except Exception:
            return s
        else:
            self.is_json = True
            for d in jo:
                jo[d] = self._parse_json(jo[d])
            return jo

    def _get_leaves(self):
        '''
        Get all leaf nodes which are allowed for data manipulation.
        :return: None
        '''
        self._args = {node.tag: node.identifier for node in self.tree.leaves()}
        return

    @staticmethod
    def _dict_to_tree(data):
        '''
        Parse dict to tree.
        :return: tree
        '''
        def _add_nodes(parent, name, identity, data):
            tree.create_node(name, identity, parent=parent, data=data)

        def _process(parent, data):
            nonlocal identity
            for i in data:
                if type(data[i]) is not dict:
                    _add_nodes(parent, i, identity, data[i])
                    identity += 1
                else:
                    _add_nodes(parent, i, identity, "")
                    parent_node = identity
                    identity += 1
                    _process(parent_node, data[i])

        tree = Tree()
        identity = 1
        tree.create_node('Root', 0)
        _process(0, data)
        return tree

    @staticmethod
    def _tree_to_dict(tree):
        '''
        Parse tree to dict.
        :param tree: A tree transformed from a dict.
        :return: dict
        '''

        def _get_dict(ptl, value):
            key = ptl[-1]
            if key == 0:
                k = list(value.keys())[0]
                v = list(value.values())[0]
                # combines several dicts together
                if k in result:
                    new_value = dict(result[k], **v)
                    result[k] = new_value
                else:
                    result[k] = v
                return
            else:
                res = {tree.nodes[key].tag:value}
                return _get_dict(ptl[:-1], res)

        paths_to_leaves = tree.paths_to_leaves()
        result = {}
        for p in paths_to_leaves:
            num = p[-1]
            value = {tree.nodes[num].tag: tree.nodes[num].data}
            _get_dict(p[:-1], value)
        return result

if __name__ == '__main__':
    import requests
    post_data = r'{"app":"exp", "test":{"module":123, "something":"test"}}'
    params = {'test':'test'}
    ob = JsonParser(post_data)
    print(ob.tree.show())
    '''
    print(ob["test"], ob["test1"], ob["test2"])
    ob2 = ob.copy()
    ob2["test2"] = "aaaa"
    requests.request("GET", "https://www.baidu.com", params=params, json=ob2.json, proxies = {"https":"http://127.0.0.1:8080"}, verify=False)
    '''


