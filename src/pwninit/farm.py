import copy
import itertools
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from math import ceil
from pathlib import Path
from urllib.parse import urljoin

import requests
from pwn import log

from pwninit.io import IOContext, NC

SERVER_TIMEOUT = 5
POST_PERIOD = 5
POST_FLAG_LIMIT = 1000
exit_event = threading.Event()


class FlagStorage:
    def __init__(self):
        self._flags = []
        self._seen = set()
        self._lock = threading.Lock()

    def add(self, flag, team_name):
        with self._lock:
            if flag not in self._seen:
                self._seen.add(flag)
                self._flags.append({'flag': flag, 'team': team_name})

    def flush(self):
        with self._lock:
            flags = self._flags[:POST_FLAG_LIMIT]
            self._flags = self._flags[POST_FLAG_LIMIT:]
            return flags

    def unflushed(self, flags):
        with self._lock:
            self._flags = flags + self._flags


def get_auth_headers(args):
    return {'Authorization': args.server_pass}


def get_config(args):
    url = urljoin(args.server_url, '/api/get_config')
    r = requests.get(url, headers=get_auth_headers(args), timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)
    return r.json()


def post_flags(args, flags):
    sploit_name = Path('exploit.py').resolve().parent.name
    data = [{'flag': item['flag'], 'sploit': sploit_name, 'team': item['team']}
            for item in flags]
    url = urljoin(args.server_url, '/api/post_flags')
    r = requests.post(url, headers=get_auth_headers(args), json=data, timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)


def once_in_a_period(period):
    for iter_no in itertools.count(1):
        start_time = time.time()
        yield iter_no
        time_spent = time.time() - start_time
        if period > time_spent:
            exit_event.wait(period - time_spent)
        if exit_event.is_set():
            break


def _post_loop(args, flag_storage, stop_event):
    while not stop_event.is_set():
        flags = flag_storage.flush()
        if flags:
            try:
                post_flags(args, flags)
                log.info('Posted %d flags' % len(flags))
            except Exception as e:
                log.warning("Can't post flags: %s" % e)
                flag_storage.unflushed(flags)
        stop_event.wait(POST_PERIOD)

    # flush restants une derniere fois apres le round
    flags = flag_storage.flush()
    if flags:
        try:
            post_flags(args, flags)
            log.info('Posted %d flags' % len(flags))
        except Exception as e:
            log.warning("Can't post remaining flags: %s" % e)
            flag_storage.unflushed(flags)


def run_one(ioctx, ctx, team_name, max_runtime, flag_format, flag_storage):
    import exploit as exploit_mod

    try:
        ioctx.reconnect()
    except Exception as e:
        log.warning('%s: connection failed — %s' % (team_name, e))
        return

    ioctx.conn.timeout = max_runtime

    try:
        result = exploit_mod.exploit(ctx, ioctx)
        flags = flag_format.findall(result) if isinstance(result, (str, bytes)) else []
        if not flags and result:
            flags = [result]
        for flag in flags:
            log.success('%s: got flag %s' % (team_name, flag))
            flag_storage.add(flag, team_name)
    except Exception as e:
        log.warning('%s: exploit failed — %s' % (team_name, e))


def run_farm(args, elf, libc, binary, kernel, prefix):
    from pwninit.helpers import PwnContext

    log.info('Connecting to farm server at %s' % args.server_url)

    try:
        config = get_config(args)
    except Exception as e:
        log.error("Can't get config from server: %s" % e)
        return 1

    teams = config['TEAMS']
    flag_format = re.compile(config['FLAG_FORMAT'])
    if not teams:
        log.error('No teams in server config')
        return 1

    log.info('Got %d teams from server' % len(teams))

    remote_port = args.remote[2]
    flag_storage = FlagStorage()

    team_ctxs = {}
    for team_name, team_addr in teams.items():
        try:
            team_args = copy.copy(args)
            team_args.remote = [NC, team_addr, remote_port]
            ioctx = IOContext(team_args, binary, kernel, prefix)
            ioctx.connect()
            ctx = PwnContext(ioctx.proc, elf, libc, binary, prefix)
            team_ctxs[team_name] = (ioctx, ctx)
        except Exception as e:
            log.warning('%s: failed to init — %s' % (team_name, e))

    if not team_ctxs:
        log.error('No teams could be initialized')
        return 1

    pool = ThreadPoolExecutor(max_workers=args.pool_size)

    try:
        for attack_no in once_in_a_period(args.attack_period):
            log.info('Launching attack #%d on %d teams' % (attack_no, len(team_ctxs)))
            max_runtime = args.attack_period / ceil(len(team_ctxs) / args.pool_size)
            log.info('Time limit per instance: %.1fs' % max_runtime)

            stop_event = threading.Event()
            post_thread = threading.Thread(
                target=_post_loop, args=(args, flag_storage, stop_event), daemon=True
            )
            post_thread.start()

            futures = [
                pool.submit(run_one, ioctx, ctx, team_name, max_runtime, flag_format, flag_storage)
                for team_name, (ioctx, ctx) in team_ctxs.items()
            ]

            for f in as_completed(futures):
                pass

            stop_event.set()
            post_thread.join()

    except KeyboardInterrupt:
        log.info('Got Ctrl+C, shutting down')
        exit_event.set()

    pool.shutdown(wait=False)
    return 0
