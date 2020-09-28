from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from .autosubmit import *


schedudler = BackgroundScheduler()
# 定义一个job类，完成想要做的事
def _nightsign():
    signmain()

def _collect():
    collect_main()

# 定时每天 17:19:07秒执行任务
schedudler.add_job(_nightsign,'cron',day_of_week='0-6',hour=21,minute=53,second=0)
schedudler.add_job(_collect,'cron',day_of_week='0-6',hour=18,minute=10,second=0)

schedudler.start()