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

username = "18305038"
password = "215756"
salt = "2wxQA9X1kJQkuncK"

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

		self.do_login(username, password) #进行登录
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
		print(filename)
		return filename




class sql():
	def __init__(self):
		self.db = MySQLdb.connect("120.78.162.170", "yyb", "playground", "scitc_jrxy", charset='utf8' )
		self.cursor = self.db.cursor()
		
if __name__ == '__main__':
	scitc_login = login()
	# mysql = sql()
	# sql = """
	# 	CREATE TABLE user (
    #     account  CHAR(20) NOT NULL,
    #     password  CHAR(20),
	# 	name CHAR(10),
    #     temperature CHAR(4),  
    #     address VARCHAR(50),
	# 	building CHAR(2),
    #     room CHAR(4),
	# 	position VARCHAR(20))"""
	# mysql.cursor.execute(sql)
	# sql = 'show columns from user;'
	# mysql.cursor.execute(sql)
	# res = mysql.cursor.fetchall()
	# print(res)

	# sql = "INSERT INTO user(account, password, name, temperature, address, building, room, position) VALUES (%s, %s, %s, %s, %s, %s, %s,);"
	# mysql.cursor.execute(sql)
	# mysql.db.commit()

	# sql = "SELECT * FROM user;"
	# mysql.cursor.execute(sql)
	# res = mysql.cursor.fetchall()
	# print(res)

	oss = oss2uploader()
	# oss.uploadImage('ST-983328-PfcUeCy9QtDHb5TE4hMz1600872449828-BTff-cas',r'C:\Users\WORKSTATION\Pictures\iu.jpg')