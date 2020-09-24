from django.http import HttpResponse
from django.shortcuts import render
from model.scitc_login import login
import json


sam_login = login()
def mylogin(request):
    content = ''
    if(request.method == 'POST'):
        print('post')
        username = request.POST.get('username','')
        password = request.POST.get('password','')
        print(username,password)
        content = sam_login.do_login(username,password)
        return HttpResponse(json.dumps('登录成功'), content_type="application/json,charset=utf-8")
    else:
        return render(request,'index.html')