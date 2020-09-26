from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from .nightsign import *


schedudler = BackgroundScheduler()
# 定义一个job类，完成想要做的事
def start_job():
    signmain()

# 定时每天 17:19:07秒执行任务
schedudler.add_job(start_job,'cron',day_of_week='0-6',hour=21,minute=53,second=0)
schedudler.start()