#coding:utf-8
 
import smtplib  # smtp服务器
from email.mime.text import MIMEText  # 邮件文本

# 邮件构建
class mysendmail():
    def __init__(self):
        self.subject = "今日校园查寝结果-" #主题
        self.sender = self.get_sender() #发送邮箱
        self.content = self.get_content() #内容
        self.password = "fnabhvtzqkipbahg" #smtp的密码
        self.message = MIMEText(self.content, "plain", "utf-8")
        self.message['From'] = self.sender
        # self.message['Subject'] = self.subject

        self.smtp = smtplib.SMTP_SSL("smtp.qq.com",465)
        self.smtp.login(self.sender,self.password)
    
    def smtp_close(self): 
        self.smtp.close()
    
    def get_sender(self):
        sender = ""
        with open("model/config/sender.txt","r",encoding="utf-8") as file:
            sender = file.read()
        return sender

    def get_content(self):
        content = ""
        with open("model/config/content.txt","r",encoding="utf-8") as file:
            content = file.read()
        return content

    def send(self,flag,recver):
        if flag:
            self.message['Subject'] =  self.subject + "成功"
        else:
            self.message['Subject'] =  self.subject + "失败"
        self.message['To'] = recver
        try:
            self.smtp.sendmail(self.sender,recver,self.message.as_string())
            print("send email success")
        except:
            print("send email fail")
        
if __name__ == "__main__":
    sample = mysendmail()
    sample.send(True,'1983890907@qq.com')
