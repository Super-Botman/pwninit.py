import requests
import subprocess
import re
import os
from pwn import ssh, success, context, log
from urllib.parse import urlparse
from ..config import config


def status(logger, text):
    context.log_level = 'info'
    logger.status(text)
    context.log_level = 'error'


def validate_url(url):
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    parsed = urlparse(url)
    if parsed.netloc not in ['www.root-me.org', 'root-me.org']:
        raise ValueError("URL must be from root-me.org")

    if '/Challenges/' not in parsed.path:
        raise ValueError("URL must be a root-me challenge URL")


def extract_ssh_credentials(html_content):
    ssh_pattern = r'ssh\s+([^\s@]+)@([^\s:]+):(\d+)'
    match = re.search(ssh_pattern, html_content)

    if not match:
        try:
            login_data = html_content.split('ssh')[1].split(
                ' ')[0].replace('//', '').replace('"', '').split(':')[1:]
            password = login_data[0]
            host = login_data[1].split('@')[1]
            port = int(login_data[2])
            return password, host, port
        except (IndexError, ValueError) as e:
            raise ValueError(
                f"Could not extract SSH credentials from page: {e}")

    password, host, port = match.groups()
    return password, host, int(port)


def run(url, path):
    validate_url(url)

    try:
        api_key = config.get_rootme_api_key()
    except ValueError as e:
        log.error(str(e))

    cookies = {"api_key": api_key}
    try:
        resp = requests.get(
            "https://api.www.root-me.org/login", cookies=cookies, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to authenticate with root-me API: {e}")

    try:
        data = resp.json()
        spip_session = data[0]['info']['spip_session']
    except (KeyError, IndexError, ValueError) as e:
        log.error(f"Failed to parse authentication response: {e}")

    cookies = {"spip_session": spip_session}
    try:
        resp = requests.get(url, cookies=cookies, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to fetch challenge page: {e}")

    try:
        password, host, port = extract_ssh_credentials(resp.text)
        chall_name = password.split('-')[-1]
    except ValueError as e:
        log.error(str(e))

    context.log_level = "error"
    try:
        s = ssh(host=host, port=port, user=password,
                password=password, timeout=10, cache=False)
    except Exception as e:
        log.error(f"Failed to establish SSH connection: {e}")

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
        (path / category).mkdir(exist_ok=True)
        chall_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.error(f"Failed to create directories: {e}")

    try:
        files = s.system("ls").recvall()[:-1]
        files = files.decode().split(" ")
        for f in files:
            if f != "":
                s.download(f, chall_path / os.path.basename(f))

        libs = s.system(f'ldd {chall_name}').recvall()
        libs = libs.decode().replace("\t", "").split("\n")[:-1]
        libs = [l.split(" => ")[-1].split(" ")[0] for l in libs]
        for l in libs:
            if "No such file or directory" not in s.system("ls % s" % l).recvall().decode().strip():
                s.download(l, chall_path / os.path.basename(l))

    except Exception as e:
        log.error(f"Failed to download files via SSH: {e}")

    status(download, "ld downloaded successfully")

    context.log_level = 'info'
    download.success("Files saved")

    return chall_path
