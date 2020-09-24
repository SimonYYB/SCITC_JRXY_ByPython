from django.http import HttpResponse
from django.shortcuts import render,reverse,redirect
from model.scitc_login import login,sql
import json


sam_login = login()
mysql = sql()
def mylogin(request):
    is_login = False
    try:
        is_login = request.session['username']
    except:
        pass
    if is_login:
         return redirect('/user')
    if(request.method == 'POST'):
        username = request.POST.get('username','')
        password = request.POST.get('password','')
        print(username,password)
        MOD_AUTH_CAS = sam_login.do_login(username,password)
        if MOD_AUTH_CAS:
            request.session['username'] = username
            request.session['MOD_AUTH_CAS'] = MOD_AUTH_CAS
            request.session['is_login'] = True
            check_database(username,password)
            sql_order = "UPDATE user SET token=(%s) WHERE account=(%s);"
            mysql.cursor.execute(sql_order,[MOD_AUTH_CAS,username])
            mysql.db.commit()
            return HttpResponse(json.dumps(1), content_type="application/json,charset=utf-8")
        else:
            return HttpResponse(json.dumps(0), content_type="application/json,charset=utf-8")
            
    else:
        return render(request,'index.html')

def check_database(account,password):
    sql_order = "SELECT * FROM user WHERE account={account};".format(account=account)
    query_flag = mysql.cursor.execute(sql_order)
    # print(query_flag)
    if not query_flag:
        print('new user creat a record')
        sql_order = "INSERT INTO USER(account,  password, email, name, temperature,  address, building, room, longitude, latitude) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        try:
            mysql.cursor.execute(sql_order,[account,password,'','','','','','','',''])
            mysql.db.commit()
        except:
            print('create fail')
