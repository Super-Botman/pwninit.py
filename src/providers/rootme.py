#!/usr/bin/env python

import requests
import sys
import os
import subprocess
from pwn import ssh, success

cookies = {
    "api_key": "375630_b8e2a2caefde6878d4de3738448aeda8897c0d9aad98eebdb39d0445ff72ce89"}
resp = requests.get(
    "https://api.www.root-me.org/login", cookies=cookies)
if resp.status_code != 200:
    raise Exception("GET /challenges/ {}".format(resp.status_code))

data = resp.json()
spip_session = data[0]['info']['spip_session']

cookies = {
    "spip_session": spip_session
}
resp = requests.get(
    sys.argv[1], cookies=cookies)
if resp.status_code != 200:
    raise Exception("GET /challenges/ {}".format(resp.status_code))


print(sys.argv[1])
data = resp.text
login = data.split('ssh')[1].split(' ')[0].replace(
    '//', '').replace('"', '').split(':')[1:]

password = login[0]
host = login[1].split('@')[1]
port = int(login[2])
chall = password.split('-')[-1]

s = ssh(host=host, port=port, user=password,
        password=password, timeout=0.5, cache=False)
s.download(chall, './chall')

name = sys.argv[1].split('/')[-1]
category = '-'.join(name.split('-')[:2])
chall = '-'.join(name.split('-')[2:])
path = category+'/'+chall

os.mkdir(category)
os.mkdir(path)
os.rename('./chall', path + '/chall')
sp = subprocess.Popen(["zsh", "-i", "-c", "cd %s && pwninit" % path])
sp.communicate()
success('chall folder created at %s' % path)
