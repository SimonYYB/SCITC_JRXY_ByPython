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

submitHeaders = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; MI 9 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 okhttp/3.8.1',
    'CpdailyStandAlone': '0',
    'Cpdaily-Extension': 'RADCSRminiMgqqlqqEeUIlGO1ivakMDZTJtYYN8fwbnuQ2vxpCSovbApowOc hQFZE4yLOkuCm0dSLgpTi27Z9JO5pnFLmjkMt6M3efLkTVuhv9qrhJ6Y4YSn xepXhPCDK8aX9PslM+hgsRPqz8JEA8IDK/F7Bw93AP1S/1Dg6XSdX/EjSb1w cbFBjlmeC6GvUSELsGD1B6DMIQbTYuGRpnnd34DiICWuko0pou0yAuHOSLSY QHQzrcGoQV/VFulz',
    'extension': '1',
    'Content-Type': 'application/json; charset=utf-8',
    'Host': 'host',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
}

mysubmitheaders = {
	'Host': 'scitc.cpdaily.com',
	'Content-Type': 'application/json',
	'Cpdaily-Extension': '7Q881vmOiX5P8Zqo42iY1D1S9CeBBvegB87cm+d2eLEtjwDmLxBqfmA87jiR FJNbjbRMm9WirZnCN4xJ5NJOhNLprSR2zZ9K9jB4UfzCKTWZI7meMmP12pcW pdIZqE5lIj2M1EZ08eriKfMykiOHdrtTBMBaCMy9F8P3Z7J0qxS7KAG7KwBA RkM6UnoZvlK0pH9SK4NCnHXqaYuRGgRg+rpjqlKjRD9jkLPKRSK9I5GTKHNR VKS5sPj+kIqX1yWjCZCmSeQBLQApUPZWlVablg==',
	'Connection': 'close',
	'Accept': '*/*',
	'Accept-Language': 'zh-cn',
	'Content-Length': '214',
	'Accept-Encoding': 'gzip, deflate',
	'User-Agent': '%E4%BB%8A%E6%97%A5%E6%A0%A1%E5%9B%AD/1 CFNetwork/1121.2.2 Darwin/19.2.0'
}

key = "ST83=@XV"#dynamic when app update
extension = {"deviceId":'dynamic',"systemName":"未来操作系统","userId":"5201314","appVersion":"8.1.13","model":"红星一号量子计算机","lon":105.895856,"systemVersion":"初号机","lat":32.424037}

mysql = sql()
sam_login = login()

#生成Cpdaily-Extension
def encrypt(text):
	k = pyDes.des(key, pyDes.CBC, b"\x01\x02\x03\x04\x05\x06\x07\x08", pad=None, padmode=pyDes.PAD_PKCS5)
	ret = k.encrypt(text)
	return base64.b64encode(ret).decode()


class oss2uploader():
	def uploadImage(self,MOD_AUTH_CAS,image_path):
		url = "https://scitc.cpdaily.com/wec-counselor-attendance-apps/student/attendance/getStsAccess"
		headers = {'content-type': 'application/json'}
		cookies = {'MOD_AUTH_CAS': MOD_AUTH_CAS}
		requests.packages.urllib3.disable_warnings()
		res = requests.post(url=url, headers=headers, cookies=cookies, data=json.dumps({}), verify=False, allow_redirects=False)
		auth = res.json().get('datas')
		accessKeyId = auth['accessKeyId']
		accessKeySecret = auth['accessKeySecret']
		securityToken = auth['securityToken']
		expiration = auth['expiration']
		endPoint = auth['endPoint']
		bucket = auth['bucket']
		filename = auth['fileName']
		bucket = oss2.Bucket(oss2.Auth(access_key_id=accessKeyId, access_key_secret=accessKeySecret), endPoint, bucket)
		with open(image_path, "rb") as f:
			data = f.read()
		bucket.put_object(key=filename, headers={'x-oss-security-token': securityToken}, data=data)
		res = bucket.sign_url('PUT', filename, 60)
		return filename

oss = oss2uploader()

def get_user_info(mysql):
	sql_order = "SELECT * FROM user;"
	mysql.cursor.execute(sql_order)
	res = mysql.cursor.fetchall()
	return res

def query_sign(user):
	url = "https://scitc.cpdaily.com/wec-counselor-attendance-apps/student/attendance/getStuAttendacesInOneDay"
	cookies = {'MOD_AUTH_CAS':user['token']}
	requests.packages.urllib3.disable_warnings()
	res = requests.post(url=url, headers=headers, cookies=cookies, data=json.dumps({}), verify=False)
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
		res = requests.post(url=url, headers=headers, cookies=cookies, data=json.dumps({}), verify=False)
		
	print(user['token'])
	if res.json()['datas']['signedTasks']:
		return {}
	if not res.json()['datas']['unSignedTasks']:
		return {}
	signInstanceWid = res.json()['datas']['unSignedTasks'][0]['signInstanceWid']
	stuSignWid = res.json()['datas']['unSignedTasks'][0]['signInstanceWid']
	rateTaskBeginTime = res.json()['datas']['unSignedTasks'][0]['rateTaskBeginTime']
	return {'signInstanceWid': signInstanceWid, 'stuSignWid': stuSignWid,'rateTaskBeginTime': rateTaskBeginTime}

def fillform_sign():
	pass

def upload_user_image(user):
	dirpath = 'static/img/' + user['account'] + '/'
	if not os.path.exists(dirpath):
		imgpath = 'static/img/yyb.ico'
	else:
		allimg = os.listdir(dirpath)
		manyimg = len(allimg)
		if not manyimg:
			imgpath = 'campushoy/static/img/yyb.ico'
		else:
			choose = random.randint(0,manyimg-1)
			imgpath = dirpath + allimg[choose]
	targetname = oss.uploadImage(user['token'],imgpath)
	return targetname
	
def submitsign(signInstanceWid,img_url,user):
	url = "https://scitc.cpdaily.com/wec-counselor-attendance-apps/student/attendance/submitSign"
	cookies = {'MOD_AUTH_CAS':user['token']}
	extension['deviceId'] = str(uuid.uuid4())
	mysubmitheaders['Cpdaily-Extension'] = encrypt(json.dumps(extension))
	requests.packages.urllib3.disable_warnings()
	res = requests.post(url=url, headers=mysubmitheaders, cookies=cookies, data=json.dumps({"signInstanceWid": signInstanceWid, "longitude": user['longitude'], "latitude": user['latitude'],
         "isMalposition": 0, "abnormalReason": "", "signPhotoUrl": img_url, "position": user['address'],
         "qrUuid": ""}), verify=False)
	print(res.text)
	msg = res.json()['message']
	return msg


def collect_query(user):
	url = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList'
	post = {
	    'pageSize': 6,
	    'pageNumber': 1
	}
	cookies = {'MOD_AUTH_CAS':user['token']}
	requests.packages.urllib3.disable_warnings()
	res = requests.post(url, headers=headers, cookies=cookies, data=json.dumps(post), verify=False)
	#MOD_AUTH_CAS 过期处理
	try:
		res.json()
	except:
		print('MOD_AUTH_CAS过期，正在获取可用MOD_AUTH_CAS')
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
        all_title = "当前体温 实测体温（℃）当前身体状况 学生公寓 寝室号"
        if formItem['isRequired'] == 1:
            sort = int(formItem['sort'])
            if formItem['title'] not in all_title:
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
                        if fieldItems[i]['content'] != formItem['value']:
                            del fieldItems[i]
            print('必填问题%d：' % sort + formItem['title'])
            print('答案%d：' % sort + str(formItem['value']))
            sort += 1
        else:
            form.remove(formItem)
    return form

def collect_submit(user,formWid,address,collectWid,schoolTaskWid,form):
    # 默认正常的提交参数json
    data = {"formWid": formWid, "address": address, "collectWid": collectWid, "schoolTaskWid": schoolTaskWid,"form": form}   
    cookies = {'MOD_AUTH_CAS':user['token']}
    extension['deviceId'] = str(uuid.uuid4())
    mysubmitheaders['Cpdaily-Extension'] = encrypt(json.dumps(extension))
    requests.packages.urllib3.disable_warnings()
    url = 'https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/collector/submitForm'
    r = requests.post(url=url, headers=mysubmitheaders, cookies=cookies, data=json.dumps(data), verify=False)
    ret = r.json()['message']
    return ret

def collect_main():
    users_data = get_user_info(mysql)
    colums = ['account', 'password', 'email', 'name', 'temperature', 'address', 'building', 'room', 'longitude', 'latitude', 'token']
    for i in users_data:
        print(i)
        user = {}
        flag = 0
        for x,y in zip(colums,i):
            if not y:
                flag = 1
            user[x] = y
        if flag:
            print('用户信息不完整')
            continue
        print("当前用户:",user['account'])
        param = collect_query(user)
        if not param:
            print('not query form need to submit')
            continue
        form = collect_fill(user,param['form'])
        ret = collect_submit(user, param['formWid'], user['address'], param['collectWid'],param['schoolTaskWid'], form)
        print(ret)

sendmessage = mysendmail()

def signmain():
	users_data = get_user_info(mysql)
	colums = ['account', 'password', 'email', 'name', 'temperature', 'address', 'building', 'room', 'longitude', 'latitude', 'token']
	for i in users_data:
		user = {}
		for x,y in zip(colums,i):
			user[x] = y
		print('当前用户:',user['account'])
		if not user['longitude']:
			user['longitude'] = '105.8882317837143'
		if not user['latitude']:
			user['latitude'] = '32.4171379928337'
		if not user['address']:
			user['address'] = '四川省广元市利州区滨河北路二段'
		param = query_sign(user)
		if param:
			now = datetime.now().strftime("%H:%M")
			print('query form need to sign')
			if now < param['rateTaskBeginTime']:
				print('too early')
				continue
			filename = upload_user_image(user)
			img_url = "https://wecres.cpdaily.com/" + filename
			print(img_url)
			ret = submitsign(param['signInstanceWid'],img_url,user)
			if ret == 'SUCCESS':
				print('提交成功')
				if user['email']:
					sendmessage.send(True,user['email'])
			elif ret == '该收集已填写无需再次填写':
				print('提交成功')
				if user['email']:
					sendmessage.send(True,user['email'])
			else:
				print("用户%s提交失败，错误为:%s"%(user['account'],message))
				if user['email']:
					sendmessage.send(False,user['email'])
		else:
			print('not found form that need sign')
	print('查寝已全部完成')

