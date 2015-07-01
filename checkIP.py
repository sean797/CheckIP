#!/opt/rh/rh-python34/root/usr/bin/python3

import http.client
import os
import requests
from systemd import journal

#### Configuration Options 
URL = "www.usermod.net/api/ip"					# Server to query public ip from
EXT_IP_FILE = os.getenv("HOME") + "/.config/current_ip"		# File to store IP
EMAIL_TO = "xxxxx@gmail.com" 				# Email to notify when IP changes
####

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

def MailgunEmail(subject,text):
    return requests.post(
        "https://api.mailgun.net/v3/sandbox.mailgun.org/messages",
        auth=("api", "key-"),
        data={"from": "Mailgun Sandbox <postmaster@sandbox.mailgun.org>",
              "to": ["Sean <{}>".format(EMAIL_TO)],
              "subject": subject,
              "text": text})

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
    MailgunEmail(subject="Home IP address has changed",text="IP address changed to {}".format(CURRENT_IP))
    log("Public IP changed to {IP}, email sent to {EMAIL}".format(IP=CURRENT_IP,EMAIL=EMAIL_TO))
else:
    log("Public IP hasn't changed")
