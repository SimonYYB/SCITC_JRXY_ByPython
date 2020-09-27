#encoding=utf-8
import requests
import json
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
import base64
import uuid
from datetime import datetime, timedelta, timezone
"""
project:	今日校园自动签到实现 By Python
author:		SCITC NIX_45
"""

def pkcs7padding(text):
	"""
	明文使用PKCS7填充
	最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
	:param text: 待加密内容(明文)
	:return:
	"""
	bs = AES.block_size  # 16
	length = len(text)
	bytes_length = len(bytes(text, encoding='utf-8'))
	# tips：utf-8编码时，英文占1个byte，而中文占3个byte
	padding_size = length if(bytes_length == length) else bytes_length
	padding = bs - padding_size % bs
	# tips：chr(padding)看与其它语言的约定，有的会使用'\0'
	padding_text = chr(padding) * padding
	return text + padding_text



def pkcs7unpadding(text):
	"""
	处理使用PKCS7填充过的数据
	:param text: 解密后的字符串
	:return:
	"""
	length = len(text)
	unpadding = ord(text[length-1])
	return text[0:length-unpadding]

def encrypt(content, key, iv):
	"""
	AES加密
	key,iv为salt与偏移量
	模式cbc
	填充pkcs7
	:param key: 密钥
	:param content: 加密内容
	:return:
	"""
	key_bytes = bytes(key, encoding='utf-8')
	iv_bytes = bytes(iv,encoding='utf-8')
	cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
	# 处理明文
	content_padding = pkcs7padding(content)
	# 加密
	encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
	# 重新编码
	result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
	return result.replace('=','%3D').replace('+','%2B').replace('/','%2F')

#移植的川信认证服务器aes js加密函数
def randomString(le):
	aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
	aes_chars_len = len(aes_chars)
	retStr = ''
	for i in range(le):
		retStr += aes_chars[math.floor(random.random() * aes_chars_len)]
	return retStr

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

#login_post SCITC认证服务器的post请求包
login_post = """
POST /authserver/login HTTP/1.1
Host: authserver.scitc.com.cn
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://authserver.scitc.com.cn/authserver/login
Content-Type: application/x-www-form-urlencoded
Content-Length: 280
Origin: http://authserver.scitc.com.cn
Connection: close
Cookie: route=25316b8ad5b2b4e29e48ce3c750d2b53; org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE=zh_CN; JSESSIONID=BiKutFHWmXqf7axis3DUBC-DWnVMtoI0FfICXXkTIzJbtQaN0KCK!1706333590
Upgrade-Insecure-Requests: 1

username={username}&password={password}&lt={lt}&dllt=userNamePasswordLogin&execution=e2s1&_eventId=submit&rmShown=1"
"""

login_data = "username={username}&password={password}&lt={lt}&dllt=userNamePasswordLogin&execution={execution}&_eventId=submit&rmShown=1"
class login():
	def __init__(self):
		self.url = "http://authserver.scitc.com.cn/authserver/login?service=https%3A%2F%2Fscitc.cpdaily.com%2Fportal%2Flogin" #SCITC认证服务器

		#POST请求包的headers
		self.headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
			'Referer': 'http://authserver.scitc.com.cn/authserver/login?service=https%3A%2F%2Fscitc.cpdaily.com%2Fportal%2Flogin',
			'Content-Type': 'application/x-www-form-urlencoded',
			'Origin': 'http://authserver.scitc.com.cn',
			'Connection': 'close'
			}
		self.salt = '' 
		self.lt = ''
		self.execution = ''
		self.cookies = requests.cookies.RequestsCookieJar()
		self.passwd = ''

		# self.do_login(username, password) #进行登录
		# self.get_jrxy_token() #获取今日校园的session token #未完成
	
	def get_jrxy_token(self, MOD_AUTH_CAS):
		url = "http://ehall.scitc.com.cn//newmobile/client/userStoreAppList"
		cookies = {'MOD_AUTH_CAS':'MOD_AUTH_'+MOD_AUTH_CAS}
		headers = {
			'Host': 'ehall.scitc.com.cn',
			'CpdailyClientType': 'CPDAILY',
			'CacheTimeValue': '0',
			'Accept-Encoding': 'gzip, deflate',
			'Accept-Language': 'zh-Hans-CN;q=1',
			'Accept': '*/*',
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36'
		}
		res = requests.get(url,cookies=cookies,headers=headers,allow_redirects=False)
		print("今日校园:")
		print(res.headers['location'])
		res = requests.get(res.headers['location'],cookies=cookies,headers=headers,allow_redirects=False)
		print(res.headers)
		print(requests.utils.dict_from_cookiejar(res.cookies))
	
	def do_login(self, username, password):
		self.get_param() #获取salt，post需要的lt，cookies
		self.passwd = encrypt(randomString(64)+password,self.salt,randomString(16)) #由于川信认证服务器为前端AES加密，需先对密码进行加密，这里得到加密和的密码
		post = login_data.format(username=username, password=self.passwd, lt=self.lt, execution=self.execution) #根据账号密码生成post数据
		res = requests.post(url=self.url,data=post,headers=self.headers,cookies=self.cookies,allow_redirects=False) #返回包,以获取ticket

		# print(res.text)
		# print(requests.utils.dict_from_cookiejar(res.cookies))

		# self.cookies['CASTGC'] = requests.utils.dict_from_cookiejar(res.cookies)['CASTGC'] #更新cookie

		html = BeautifulSoup(res.text,'html.parser')
		new_url = html.find_all('a')[0].get('href') #提取带ticket的url，以获取acw_tc 以及MOD_AUTH_CAS
		print(new_url)
		if new_url == '#':
			print('login fail, please check your account and password')
			return False
		new_header = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36',
			'Sec-Fetch-Site': 'cross-site',
			'Sec-Fetch-Mode': 'navigate',
			'Sec-Fetch-User': '?1',
			'Sec-Fetch-Dest': 'document',
			'Referer': 'http://authserver.scitc.com.cn/authserver/login?service=https%3A%2F%2Fscitc.cpdaily.com%2Fportal%2Flogin'
		}
		# print("new_url:",new_url)
		requests.packages.urllib3.disable_warnings()
		res = requests.get(new_url,headers=new_header,verify=False,allow_redirects=False) #拦截302，截取MOD_AUTH_CAS acw_tc
		MOD_AUTH_CAS = requests.utils.dict_from_cookiejar(res.cookies)['MOD_AUTH_CAS']
		acw_tc = requests.utils.dict_from_cookiejar(res.cookies)['acw_tc']
		info = """
----------------------------------------------------------------------------------
|MOD_AUTH_CAS  | {MOD_AUTH_CAS}           |
|acw_tc        | {acw_tc}  |
----------------------------------------------------------------------------------
"""
		print("Get MOD_AUTH_CAS:")
		print(info.format(MOD_AUTH_CAS=MOD_AUTH_CAS,acw_tc=acw_tc))
		return MOD_AUTH_CAS
	

	def get_param(self):
		r = requests.get(self.url)
		self.cookies = requests.utils.dict_from_cookiejar(r.cookies)
		soup = BeautifulSoup(r.text,'html.parser')
		pattern = r'var pwdDefaultEncryptSalt = "(.*)";'
		self.salt = str(re.search(pattern,soup.text))[-20:-4]
		self.lt = soup.select('input[name="lt"]')[0].get('value')
		self.execution = soup.select('input[name="execution"]')[0].get('value')
		info = """
-------------------------------------------------------------------------------------------------------------------------------------------
|salt  | {salt}                                                                                                                 |
|lt    | {lt}                                                                  |
|exec  | {exec}                                                                                                                             |
|cookie| {cookies}   |
-------------------------------------------------------------------------------------------------------------------------------------------
"""
		print(info.format(salt=self.salt,lt=self.lt,exec=self.execution,cookies=self.cookies))

#今日校园，获取信息表单post请求包	
"""
POST /wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList HTTP/1.1
Host: scitc.cpdaily.com
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
Accept-Language: zh-cn
Accept-Encoding: gzip, deflate
Content-Type: application/json
Origin: https://scitc.cpdaily.com
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4428817920)cpdaily/8.2.4  wisedu/8.2.4
Connection: close
Referer: https://scitc.cpdaily.com/wec-counselor-collector-apps/stu/mobile/index.html
Content-Length: 29
Cookie: MOD_AUTH_CAS=ST-972555-0P7vnJecu7XRJdMbrR0b1600823442410-BTff-cas;

{"pageSize":6,"pageNumber":1}
"""

#为查寝上传照片
"""
1.获取使用带cookie的post请求获取认证信息
2.上传图片
3.获取上传后的图片名，并返回
"""
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




class sql():
	def __init__(self):
		self.db = MySQLdb.connect("120.78.162.170", "yyb", "playground", "scitc_jrxy", charset='utf8' )
		self.cursor = self.db.cursor()
		



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
	print(res.json())
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
	dirpath = 'campushoy/static/img/' + user['account'] + '/'
	if not os.path.exists(dirpath):
		imgpath = 'campushoy/static/img/yyb.ico'
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
	# submitHeaders['Cpdaily-Extension'] = header_encrypt(json.dumps(extension))
	submitHeaders['Cpdaily-Extension'] = "7Q881vmOiX5P8Zqo42iY1D1S9CeBBvegB87cm+d2eLEtjwDmLxBqfmA87jiR FJNbjbRMm9WirZnCN4xJ5NJOhNLprSR2zZ9K9jB4UfzCKTWZI7meMmP12pcW pdIZqE5lIj2M1EZ08eriKfMykiOHdrtTBMBaCMy9F8P3Z7J0qxS7KAG7KwBA RkM6UnoZvlK0i5X+9cRZ1yiLBIjnJAoXQ33qinUcJWY2Sbwoa5Oz5FOoDYwY ifZihXDjj34mb5SyHR+DjZlxnrRocvQqmTRneQ=="
	print("Cpdaily-Extension:",submitHeaders['Cpdaily-Extension'])
	requests.packages.urllib3.disable_warnings()
	res = requests.post(url=url, headers=submitHeaders, cookies=cookies, data=json.dumps({"signInstanceWid": signInstanceWid, "longitude": user['longitude'], "latitude": user['latitude'],
         "isMalposition": 0, "abnormalReason": "", "signPhotoUrl": img_url, "position": user['address'],
         "qrUuid": ""}), verify=False)
	msg = res.json()['message']
	return msg


def signmain():
	users_data = get_user_info(mysql)
	colums = ['account', 'password', 'email', 'name', 'temperature', 'address', 'building', 'room', 'longitude', 'latitude', 'token']
	nums = 0
	for i in users_data:
		user = {}
		for x,y in zip(colums,i):
			user[x] = y
		
		filename = upload_user_image(user)
		print(filename)
		param = query_sign(user)
		if param:
			now = datetime.now().strftime("%H:%M")
			print('query form need to sign')
			if now < param['rateTaskBeginTime']:
				print('too early')
				continue
			filename = upload_user_image(user)
			img_url = "https://wecres.cpdaily.com/" + filename
			ret = submitsign(param['signInstanceWid'],img_url,user)
			if ret == 'SUCCESS':
				print('提交成功')
				sendmessage(user['email'],'ret_success.txt')
			elif ret == '该收集已填写无需再次填写':
				sendmessage(user['email'],'ret_success.txt')
			else:
				print("用户%s提交失败，错误为:%s"%(user['account'],message))
				sendMessage(user['email'],'ret_fail.txt')
		else:
			print('not found form that need sign')
	print('查寝已全部完成')
		

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
		MOD_AUTH_CAS = scitc_login.do_login(user['account'],user['password'])
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
                        if fieldItems[i]['content'] != formItem['value']:
                            del fieldItems[i]
            log('必填问题%d：' % sort + formItem['title'])
            log('答案%d：' % sort + str(formItem['value']))
            sort += 1
        else:
            form.remove(formItem)
    return form

def collect_submit():
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
        ret = collect_submit(user, prama['formWid'], user['address'], prama['collectWid'],prama['schoolTaskWid'], form)
        print(ret)


if __name__ == '__main__':
	scitc_login = login()
	mysql = sql()

	#查询表结构
	# mysql.cursor.execute(sql)
	# sql = 'show columns from user;'
	# mysql.cursor.execute(sql)
	# res = mysql.cursor.fetchall()
	# print(res)


	#查询数据库所有用户信息
	# sql = "SELECT * FROM user;"
	# mysql.cursor.execute(sql)
	# res = mysql.cursor.fetchall()
	# print(res)

	oss = oss2uploader()

	# signmain()
	collect_main()
