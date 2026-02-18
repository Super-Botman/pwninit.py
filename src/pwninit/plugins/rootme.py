import hashlib
import json
import os
import re
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from pwn import context, log, parse_ldd_output, ssh, success

from pwninit.config import config
from pwninit.plugins import Plugin, arg


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
            raise ValueError(f"Could not extract SSH credentials from page: {e}")
    password, host, port = match.groups()
    return password, host, int(port)


def solve_anubis_challenge(session, url):
    progress = log.progress("Anubis Challenge")
    progress.status("Fetching challenge...")
    response = session.get(url)

    preact_match = re.search(
        r'<script id="preact_info" type="application/json">(.+?)</script>',
        response.text, re.DOTALL
    )
    if not preact_match:
        progress.success("No challenge found (already bypassed)")
        return response

    preact_data = json.loads(preact_match.group(1))
    challenge_string = preact_data['challenge']
    difficulty = preact_data['difficulty']
    redir_url = preact_data['redir']

    progress.status("Computing hash...")
    result = hashlib.sha256(challenge_string.encode()).hexdigest()

    wait_time = (difficulty * 125) / 1000.0
    progress.status(f"Waiting {wait_time}s...")
    time.sleep(wait_time)

    parsed_original = urlparse(response.url)
    base = f"{parsed_original.scheme}://{parsed_original.netloc}"
    pass_url = urljoin(base, redir_url) if not redir_url.startswith('http') else redir_url

    parsed = urlparse(pass_url)
    params = parse_qs(parsed.query)
    params['result'] = [result]
    new_query = urlencode(params, doseq=True)
    pass_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    progress.status("Submitting solution...")
    final_response = session.get(pass_url, allow_redirects=True)

    if final_response.status_code == 200 and "Oh noes!" not in final_response.text:
        progress.success("Challenge bypassed!")
    else:
        progress.failure("Challenge failed")
        error_match = re.search(r'<p>(.+?)</p>', final_response.text)
        if error_match:
            log.error(f"Server response: {error_match.group(1)}")

    return final_response


class Plugin(Plugin):
    name = "rootme"
    description = "Fetch challenge binary and libs from root-me.org via SSH"
    provide_args = [
        arg("url", help="Root-me challenge URL"),
        arg("--api-key", help="Override root-me API key (default: from config)", default=None),
        arg("--path", help="Set the relative path where all the files will be downloaded (default: categorie/name)")
    ]

    def provide(self, args, path):
        url = args.url
        validate_url(url)

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

        try:
            api_key = args.api_key or config.get('rootme_api_key', env_var='ROOTME_API_KEY')
        except ValueError as e:
            log.error(str(e))

        cookies = {"api_key": api_key}
        try:
            resp = session.get(
                "https://api.www.root-me.org/login", cookies=cookies, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            log.error(f"Failed to authenticate with root-me API: {e}")

        try:
            resp = solve_anubis_challenge(session, url)
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
        chall_path = path / category / chall_filename if not args.path else path / args.path

        try:
            (path / category).mkdir(exist_ok=True)
            chall_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log.error(f"Failed to create directories: {e}")

        try:
            files = s.run("ls -l").recvall().decode().split('\n')[1:-1]
            for f in files:
                f = f.split(' ')[-1]
                if f != "":
                    s.download(f, chall_path / os.path.basename(f))
                    download.status(f'downloading {f}')

            libs = parse_ldd_output(s.system(f'ldd {chall_name}').recvall().decode())
            for l in libs:
                if "No such file or directory" not in s.system("ls % s" % l).recvall().decode().strip():
                    s.download(l, chall_path / os.path.basename(l))
                    download.status(f'downloading {l}')
        except Exception as e:
            log.error(f"Failed to download files via SSH: {e}")

        context.log_level = 'info'
        download.success("Files saved")
        s.close()
        return chall_path
