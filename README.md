CheckIP
=========
Python3 script to email public IP address every time it changes


Installation
============
Install dependencies:

    sudo yum install git python3-pip gcc python3-devel systemd-devel
    pip-python3 install git+http://github.com/systemd/python-systemd.git#egg=systemd
    pip install requests


User defined options are at the top of checkIP.py. You only need to define SMTP options or Mailgun.
