import requests
import json
import io
import random
import time
import re
import pyDes
import base64
import uuid
import sys
import os
import hashlib
from Crypto.Cipher import AES


#生成
def encrypt(text):
    k = pyDes.des(key, pyDes.CBC, b"\x01\x02\x03\x04\x05\x06\x07\x08", pad=None, padmode=pyDes.PAD_PKCS5)
    ret = k.encrypt(text)
    return base64.b64encode(ret).decode()

key = "ST83=@XV"#dynamic when app update
extension = {"deviceId":"none","systemName":"未来操作系统","userId":"5201314","appVersion":"8.1.13","model":"红星一号量子计算机","lon":105.8882317837143,"systemVersion":"初号机","lat":32.4171379928337}
extension['deviceId'] = str(uuid.uuid4())
print({"Cpdaily-Extension": encrypt(json.dumps(extension))})
extension['deviceId'] = str(uuid.uuid4())
print({"Cpdaily-Extension": encrypt(json.dumps(extension))})
extension['deviceId'] = str(uuid.uuid4())
print({"Cpdaily-Extension": encrypt(json.dumps(extension))})
extension['deviceId'] = str(uuid.uuid4())
print({"Cpdaily-Extension": encrypt(json.dumps(extension))})


def submitsign(signInstanceWid,img_url,user):
	url = "https://scitc.cpdaily.com/wec-counselor-attendance-apps/student/attendance/submitSign"
	cookies = {'MOD_AUTH_CAS':user['token']}
	extension['deviceId'] = str(uuid.uuid4())
	mysubmitheaders['Cpdaily-Extension'] = encrypt(json.dumps(extension))
	requests.packages.urllib3.disable_warnings()
	res = requests.post(url=url, headers=mysubmitheaders, cookies=cookies, data=json.dumps({"signInstanceWid": signInstanceWid, "longitude": user['longitude'], "latitude": user['latitude'],
         "isMalposition": 0, "abnormalReason": "", "signPhotoUrl": img_url, "position": user['address'],
         "qrUuid": ""}), verify=False)
	try：
		msg = res.json()['message']
	except:
		msg = '提交出错,原因大概率为Cpdaily_Extension错误'
	return msg