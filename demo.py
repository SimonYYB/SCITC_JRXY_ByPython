#encoding=utf-8
import requests
import json
import math
import random
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
import base64
import re

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
	key,iv使用同一个
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
		self.url = "http://authserver.scitc.com.cn/authserver/login" #SCITC认证服务器

		#POST请求包的headers
		self.headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0',
			'Referer': 'http://authserver.scitc.com.cn/authserver/login',
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
	
	def do_login(self, username, password):
		self.get_param() #获取salt，post需要的lt，cookies
		self.passwd = encrypt(randomString(64)+password,self.salt,randomString(16)) #由于川信认证服务器为前端AES加密，需先对密码进行加密，这里得到加密和的密码
		post = login_data.format(username=username, password=self.passwd, lt=self.lt, execution=self.execution) #根据账号密码生成post数据
		res = requests.post(url=self.url,data=post,headers=self.headers,cookies=self.cookies,allow_redirects=False) #截取302返回包,以获取cookie以及token
		self.cookies['CASTGC'] = requests.utils.dict_from_cookiejar(res.cookies)['CASTGC']
		print("new cookies:",self.cookies)
		new_url = "http://authserver.scitc.com.cn/authserver/login"
		res = requests.get(new_url,cookies=self.cookies)
		print(res.text)
	

	def get_param(self):
		r = requests.get(self.url)
		self.cookies = requests.utils.dict_from_cookiejar(r.cookies)
		soup = BeautifulSoup(r.text,'html.parser')
		pattern = r'var pwdDefaultEncryptSalt = "(.*)";'
		self.salt = str(re.search(pattern,soup.text))[-20:-4]
		self.lt = soup.select('input[name="lt"]')[0].get('value')
		self.execution = soup.select('input[name="execution"]')[0].get('value')
		print("cookies:\t",self.cookies)
		print("salt:\t",self.salt)
		print("lt:\t",self.lt)
		print("execution:\t",self.execution)
		



if __name__ == '__main__':
	# ret = encrypt(randomString(64)+password,salt,randomString(16))
	# print(ret)

	scitc_login = login()
	
