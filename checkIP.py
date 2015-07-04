#!/opt/rh/rh-python34/root/usr/bin/python3

import http.client
import os
import requests
from systemd import journal
import argparse
import smtplib

#### Configuration Options 
URL = "www.usermod.net/api/ip"					# Server to query public ip from
EXT_IP_FILE = os.getenv("HOME") + "/.current_ip"		# File to store IP
recipient  = "" 						# Email to notify when changes
sender = ""
mailgun_sandbox = ""						# Your Mailgun sandbox code
mailgun_api = ""            					# Your Mailgun API key
smtp_user = ""							# SMTP User
smtp_pass = ""							# SMTP Password
smtp_host = ""							# SMTP host
####

parser = argparse.ArgumentParser(description='CheckIP will email your public IP address, run from cron to email when it change')
mail_method = parser.add_mutually_exclusive_group(required=True)
mail_method.add_argument('-s','--smtp', help='Use SMTP server',action='store_true')
mail_method.add_argument('-m','--mailgun', help='Use mailgun',action='store_true')
args = parser.parse_args()

mailgun = args.mailgun
smtp = args.smtp

HOST, REQUEST = URL.split("/",1)
REQUEST = "/" + REQUEST

# Functions
def currentIP(host=HOST, request=REQUEST):
    conn = http.client.HTTPConnection(host)
    try:
        conn.request("GET", request)
    except:
        log("Issue getting public IP from {}".format(HOST + REQUEST)) 
        exit(2)
    r1 = conn.getresponse()
    if r1.status == 200:
        data = r1.read()
        data_str = data.__str__()
        currentip = data_str.split('\'')
        return currentip[1]
    else:
        log("Issue getting public IP: Got {ERROR} error from from {URL}".format(URL=HOST + REQUEST,ERROR=r1.status))
        exit(3)

def knownIP(file=EXT_IP_FILE):
    try:
        ext_ip_file = open(file)    
    except FileNotFoundError:
        ext_ip_file = open(file, "w")
        ext_ip_file.close()
        log("No public IP known, assuming first run...")
        known_ip = ""
        return known_ip
    else:
        data = ext_ip_file.read()
        known_ip = data.strip('\n')
        return known_ip

def email(subject,msg):
    if mailgun:
        email = requests.post(
            "https://api.mailgun.net/v3/{}.mailgun.org/messages".format(mailgun_sandbox),
            auth=("api", mailgun_api),
            data={"from": "Mailgun Sandbox <postmaster@sandbox.mailgun.org>",
                 "to": [recipient],
                  "subject": subject,
                  "text": msg})
        if email.status_code != 200:
            log("Got {} using mailguns API".format(email.status_code))
            return False
        else:
            return True
    elif smtp:
        try:
            email = smtplib.SMTP(smtp_host)
            email.starttls()
            email.login(smtp_user,smtp_pass)
            email.sendmail(from_addr=sender,to_addrs=recipient,msg="Subject:{subject} \n\n {msg} \n\n".format(subject=subject,msg=msg))
        except Exception as error:
            log(str(error))
            return False
        email.quit()
        return True 

def log(message,level=6,app="checkIP.py"):
    log = journal.stream(app,level)
    log.write(message)

CURRENT_IP = currentIP()
KNOWN_IP = knownIP()

if KNOWN_IP != CURRENT_IP:
    ext_ip_file = open(EXT_IP_FILE, "w+t")
    ext_ip_file.flush()
    ext_ip_file.write(CURRENT_IP)
    ext_ip_file.write("\n")
    ext_ip_file.close()
    sent = email(subject="Home IP address has changed",msg="IP address changed to {}".format(CURRENT_IP))
    if sent:
        log("Public IP changed to {IP}, written to file & email sent to {EMAIL}".format(IP=CURRENT_IP,EMAIL=recipient))
    else:
        log("Public IP changed to {IP}, written to file but error occored sending email to {EMAIL}".format(IP=CURRENT_IP,EMAIL=recipient))
else:
    log("Public IP hasn't changed")
