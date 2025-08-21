import requests
import sys
import os
from pwn import ssh, success, context, log


def status(logger, text):
    context.log_level = 'info'
    logger.status(text)
    context.log_level = 'error'


def run(url, path):
    cookies = {
        "api_key": "375630_7050c5f61159cca8261a0c5c63d438b59135b76a3179334e993f807cbdd5c0ce"}
    resp = requests.get(
        "https://api.www.root-me.org/login", cookies=cookies)
    if resp.status_code != 200:
        raise Exception("GET /challenges/ {}".format(resp.status_code))

    data = resp.json()
    spip_session = data[0]['info']['spip_session']

    cookies = {
        "spip_session": spip_session
    }
    resp = requests.get(url, cookies=cookies)
    if resp.status_code != 200:
        raise Exception("GET /challenges/ {}".format(resp.status_code))

    print(sys.argv[1])
    data = resp.text
    login = data.split('ssh')[1].split(' ')[0].replace(
        '//', '').replace('"', '').split(':')[1:]

    password = login[0]
    host = login[1].split('@')[1]
    port = int(login[2])
    chall_name = password.split('-')[-1]

    context.log_level = "error"
    s = ssh(host=host, port=port, user=password,
            password=password, timeout=0.5, cache=False)

    if not s.connected():
        return ""

    context.log_level = 'info'
    success("Connected to ssh")
    download = log.progress("Downloading files")
    context.log_level = 'error'

    name = url.split('/')[-1]
    category = '-'.join(name.split('-')[:2])
    chall_filename = '-'.join(name.split('-')[2:])
    chall_path = path / category / chall_filename

    try:
        os.mkdir(path / category)
        os.mkdir(chall_path)
    except FileExistsError:
        pass

    s.download(chall_name, chall_path / './chall')
    status(download, "chall downloaded successfully")

    s.download('/challenge/app-systeme/ch6/lib/libc.so.6',
               chall_path / 'libc.so.6')
    status(download, "libc downloaded successfully")

    s.download('/challenge/app-systeme/ch6/lib/ld-linux-x86-64.so.2',
               chall_path / 'ld-linux-x86-64.so.2')

    status(download, "ld downloaded successfully")

    context.log_level = 'info'
    download.success("Files saved")

    os.system('chmod +x %s' % (chall_path / 'chall'))
    os.system('chmod +x %s' % (chall_path / 'libc.so.6'))
    os.system('chmod +x %s' % (chall_path / 'ld-linux-x86-64.so.2'))

    return chall_path
