from django.http import HttpResponse
from django.shortcuts import render,reverse,redirect
from django.contrib.auth import authenticate, login, logout #user django already has auth
from model.scitc_login import login
import json
import os
from model.scitc_login import sql

mysql = sql()
def user_logout(request):
    logout(request)
    return redirect('/')

def user_info(request):
    try:
        is_login = request.session['username']
    except:
        return redirect('/')
    content = {}
    sql_order = "select * from user where account={account}".format(account=request.session['username'])
    query_flag = mysql.cursor.execute(sql_order)
    if query_flag:
        ret = mysql.cursor.fetchone()
        # print(ret)
        key = ('account', 'password', 'email', 'name', 'temperature', 'address', 'building', 'room', 'longitude', 'latitude')
        for i,j in zip(key,ret):
            content[i] = j
        # print(content)
    return render(request,'user.html',content)

def user_update(request):
    if request.method == 'POST':
        print('update')
        account = request.session['username']
        name = request.POST.get('name','')
        email = request.POST.get('email','')
        temperature = request.POST.get('temperature','')
        address = request.POST.get('address','')
        building = request.POST.get('building','')
        room = request.POST.get('room','')
        longitude = request.POST.get('longitude','')
        latitude = request.POST.get('latitude','')
        print([name, email, temperature, address, building, room, longitude, latitude, account])
        sql_order = "UPDATE user SET name=(%s), email=(%s), temperature=(%s), address=(%s), building=(%s), room=(%s), longitude=(%s), latitude=(%s) WHERE account=(%s);"
        mysql.cursor.execute(sql_order,[name, email, temperature, address, building, room, longitude, latitude, account])
        mysql.db.commit()
        return HttpResponse(json.dumps("更新成功"), content_type="application/json,charset=utf-8")
        # except:
        #     return HttpResponse(json.dumps("更新失败"), content_type="application/json,charset=utf-8")

    else:
        return HttpResponse(json.dumps("违规请求"), content_type="application/json,charset=utf-8")

def user_img_upload(request):
    print("uploading running")
    if request.method == 'POST':
        obj = request.FILES.get('myimg')  # 获取对象
        if not obj:
            return render(request, 'user.html')
        filepath = 'static/img/' + request.session['username'] + '/'
        print(obj.name)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        obname = filepath + obj.name  # 保存路径加上传文件的文件名
        with open(obname, 'wb+') as f:
            for chunk in obj.chunks():
                f.write(chunk)
        return HttpResponse(json.dumps("上传成功"), content_type="application/json,charset=utf-8")
    return render(request, 'user.html')