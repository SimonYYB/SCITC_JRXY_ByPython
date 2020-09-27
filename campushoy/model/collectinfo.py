#encoding=utf-8
import requests
import json
import io
import math
import random
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
import base64
import re
import MySQLdb
import oss2
import os
import pyDes
import uuid
from datetime import datetime, timedelta, timezone
from .scitc_login import login,sql
from .sendemail import mysendmail


headers = {
    'Accept': 'application/json, text/plain, */*',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; vmos Build/LMY48G; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.100 Mobile Safari/537.36  cpdaily/8.2.2 wisedu/8.2.2',
    'content-type': 'application/json',
    'Accept-Encoding': 'gzip,deflate',
    'Accept-Language': 'zh-CN,en-US;q=0.8',
    'Content-Type': 'application/json;charset=UTF-8'
}

def collect_query(user):
    url = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList'
    post = {
        'pageSize': 6,
        'pageNumber': 1
    }
    cookies = {'MOD_AUTH_CAS':user['token']}
    res = requests.post(url, headers=headers, cookies=cookies, data=json.dumps(post), verify=False)
    #MOD_AUTH_CAS 过期处理
    try:
        res.json()
    except:
        MOD_AUTH_CAS = sam_login.do_login(user['account'],user['password'])
        user['token'] = MOD_AUTH_CAS
        cookies = {'MOD_AUTH_CAS':MOD_AUTH_CAS}
        sql_order = "UPDATE user SET token=(%s) WHERE account=(%s);"
        mysql.cursor.execute(sql_order,[MOD_AUTH_CAS,user['account']])
        mysql.db.commit()
        requests.packages.urllib3.disable_warnings()
        res = requests.post(url, headers=headers, cookies=cookies, data=json.dumps(post), verify=False)
    if not res.json()['datas']['rows']:
        return None
    collectWid = res.json()['datas']['rows'][0]['wid']
    formWid = res.json()['datas']['rows'][0]['formWid']

    detailCollector = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/detailCollector'
    res = requests.post(url=detailCollector, headers=headers, cookies=cookies,  data=json.dumps({"collectorWid": collectWid}), verify=False)
    schoolTaskWid = res.json()['datas']['collector']['schoolTaskWid']

    getFormFields = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/getFormFields'
    res = requests.post(url=getFormFields, headers=headers, cookies=cookies, data=json.dumps({"pageSize": 100, "pageNumber": 1, "formWid": formWid, "collectorWid": collectWid}), verify=False)
    form = res.json()['datas']['rows']

    return {'collectWid': collectWid, 'formWid': formWid, 'schoolTaskWid': schoolTaskWid, 'form': form}

def collect_fill(user,form):
    for formItem in form[:]:
        # 只处理必填项
        default['title'] = "当前体温 实测体温（℃）当前身体状况 学生公寓 寝室号"
        if formItem['isRequired'] == 1:
            sort = int(formItem['sort'])
            if formItem['title'] not in default['title']:
                print('意料之外的问题',formItem['title'])

            # 文本直接赋值
            if formItem['fieldType'] == 1:
                if formItem['title'] in '实测体温（℃）':
                    formItem['value'] = user['temperature']
                if formItem['title'] in '寝室号':
                    formItem['value'] = user['room']

            # 单选框需要删掉多余的选项
            if formItem['fieldType'] == 2:
                # 填充默认值
                if formItem['title'] in '当前体温':
                    formItem['value'] = '<37.3℃'
                    fieldItems = formItem['fieldItems']
                    for i in range(0, len(fieldItems))[::-1]:
                        if fieldItems[i]['content'] != formItem['value']:
                            del fieldItems[i]
                if formItem['title'] in '当前身体状况':
                    formItem['value'] = '正常'
                    fieldItems = formItem['fieldItems']
                    for i in range(0, len(fieldItems))[::-1]:
                        if fieldItems[i]['content'] != formItem['value']:
                            del fieldItems[i]
                if formItem['title'] in '学生公寓':
                    formItem['value'] = user['building']
                    fieldItems = formItem['fieldItems']
                    for i in range(0, len(fieldItems))[::-1]:
                        if fieldItems[i]['content'] != formItem['value']':
                            del fieldItems[i]
            log('必填问题%d：' % sort + formItem['title'])
            log('答案%d：' % sort + str(formItem['value']))
            sort += 1
        else:
            form.remove(formItem)
    return form


def collect_submit(user, formWid, address, collectWid, schoolTaskWid, form):
    # 默认正常的提交参数json
    data = {"formWid": formWid, "address": address, "collectWid": collectWid, "schoolTaskWid": schoolTaskWid,"form": form}   
    cookies = {'MOD_AUTH_CAS':user['token']}
    extension['deviceId'] = str(uuid.uuid4())
    mysubmitheaders['Cpdaily-Extension'] = encrypt(json.dumps(extension))
    requests.packages.urllib3.disable_warnings()
    url = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/submitForm'
    r = session.post(url=url, headers=mysubmitheaders, data=json.dumps(data), verify=False)
    ret = r.json()['message']
    return ret

def collect_main():
    users_data = get_user_info(mysql)
    colums = ['account', 'password', 'email', 'name', 'temperature', 'address', 'building', 'room', 'longitude', 'latitude', 'token']
    for i in users_data:
        user = {}
        flag = 0
        for x,y in zip(colums,i):
            if not y:
                flag = 1
            user[x] = y
        if flag:
            continue
        param = collect_query(user)
        if not param:
            print('not query form need submit')
            continue
        form = collect_fill(param['form'])
        ret = collect_submit(user, prama['formWid'], user['address'], prama['collectWid'],prama['schoolTaskWid'], form)
        print(ret)