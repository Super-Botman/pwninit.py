import copy
import itertools
import queue
import re
import threading
import time
from math import ceil
from pathlib import Path
from urllib.parse import urljoin

import requests
from pwn import log

from pwninit.io import IOContext
from pwninit.helpers import PwnContext
import pwninit.io as _io

_farm_local = threading.local()

class _ThreadLocalIOProxy:
    """Forwards all attribute access to the calling thread's IOContext."""
    def __getattr__(self, name):
        return getattr(_farm_local.ioctx, name)
    def __setattr__(self, name, value):
        setattr(_farm_local.ioctx, name, value)

_io.ioctx = _ThreadLocalIOProxy()

def _patched_set_ctx(new_ctx):
    _farm_local.ioctx = new_ctx

_io.set_ctx = _patched_set_ctx

SERVER_TIMEOUT = 5
POST_PERIOD = 5
POST_FLAG_LIMIT = 1000
exit_event = threading.Event()


class FlagStorage:
    def __init__(self):
        self._flags = []
        self._seen = set()
        self._lock = threading.Lock()

    def add(self, flag, team_name, service):
        with self._lock:
            if flag not in self._seen:
                self._seen.add(flag)
                self._flags.append({'flag': flag, 'team': team_name, 'service': service})

    def flush(self):
        with self._lock:
            flags = self._flags[:POST_FLAG_LIMIT]
            self._flags = self._flags[POST_FLAG_LIMIT:]
            return flags

    def unflushed(self, flags):
        with self._lock:
            self._flags = flags + self._flags


class FlagIDStorage:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def update(self, chall, data):
        with self._lock:
            self._data[chall] = data

    def get(self, chall, team=None):
        with self._lock:
            if chall not in self._data:
                return None
            if team is None:
                return self._data[chall]
            return self._data[chall].get(str(team))


def get_auth_headers(args):
    return {'Authorization': args.password}

def set_farm_config(args, config):
    url = urljoin(args.url, '/api/set_config')
    r = requests.post(url, headers=get_auth_headers(args), json=config, timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)
    return r.json()

def get_farm_config(args):
    url = urljoin(args.url, '/api/get_config')
    r = requests.get(url, headers=get_auth_headers(args), timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)
    return r.json()


def get_flagids(args, *keys):
    path = '/'.join(str(k) for k in keys)
    url = urljoin(args.url, f'/api/get_flagid/{path}')
    r = requests.get(url, headers=get_auth_headers(args), timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)
    return r.json()


def post_flags(args, flags):
    sploit_name = Path('exploit.py').resolve().parent.name
    data = [{'flag': item['flag'], 'sploit': sploit_name, 'team': item['team'], 'service': item['service']}
            for item in flags]
    url = urljoin(args.url, '/api/post_flags')
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

    flags = flag_storage.flush()
    if flags:
        try:
            post_flags(args, flags)
            log.info('Posted %d flags' % len(flags))
        except Exception as e:
            log.warning("Can't post remaining flags: %s" % e)
            flag_storage.unflushed(flags)


def _run_one(exploit, ioctx, ctx, flag_ids, team_name, max_runtime, flag_format, flag_storage, chall):
    try:
        ioctx.connect(enable_log=False)
    except Exception as e:
        log.warning('%s: connection failed - %s' % (team_name, e))
        return

    ioctx.conn.timeout = max_runtime

    try:
        result = exploit(ctx, ioctx, flag_ids)
        flags = flag_format.findall(result) if isinstance(result, (str, bytes)) else []
        if not flags and result:
            flags = [result]
        for flag in flags:
            log.success('%s: got flag %s' % (team_name, flag))
            flag_storage.add(flag, team_name, chall)
    except Exception as e:
        log.warning('%s: exploit failed - %s' % (team_name, e))
    finally:
        ioctx.close(enable_log=False)


def _team_worker(team_name, ioctx, ctx, exploit, config, args, flag_format, flag_storage, flagid_storage, task_queue, stop_event):
    """Persistent per-team thread. Binds its IOContext into the thread-local
    proxy once at startup, then waits for round tasks."""
    import pwninit.io as io
    import pwninit.helpers as helpers

    io.set_ctx(ioctx)
    helpers.set_ctx(ctx)

    while not stop_event.is_set():
        try:
            max_runtime = task_queue.get(timeout=1)
        except queue.Empty:
            continue

        flag_ids = flagid_storage.get(config.challname, team_name)
        try:
            _run_one(exploit, ioctx, ctx, flag_ids, team_name, max_runtime, flag_format, flag_storage, config.challname)
        finally:
            task_queue.task_done()


def run_farm(args, config, exploit):
    log.info('Connecting to farm server at %s' % args.url)

    if hasattr(config, 'farm_config'):
        set_farm_config(args, config.farm_config)

    try:
        farm_config = get_farm_config(args)
        log.info(f'Flag format: {farm_config["FLAG_FORMAT"]}')
        log.info(f'Flag lifetime: {farm_config["FLAG_LIFETIME"]}')
        if not args.period:
            args.period = farm_config["FLAG_LIFETIME"]
        else:
            args.period = 55
    except Exception as e:
        log.error("Can't get farm_config from server: %s" % e)
        return 1

    teams = farm_config['TEAMS']
    flag_format = re.compile(farm_config['FLAG_FORMAT'])
    if not teams:
        log.error('No teams in server farm_config')
        return 1

    log.info('Got %d teams from server' % len(teams))

    flag_storage = FlagStorage()
    flagid_storage = FlagIDStorage()

    team_ctxs = {}
    for team_name, team_addr in teams.items():
        try:
            host = team_addr
            if ':' in host:
                host = team_addr.split(':')[0]
                port = int(team_addr.split(':')[1])

            team_args = copy.copy(args)
            team_args.remote.host = host
            if port:
                team_args.remote.port = port
            ioctx = IOContext(team_args, config)
            ctx = PwnContext(ioctx.proc, config.binary, config.libc)
            team_ctxs[team_name] = (copy.deepcopy(ioctx), copy.deepcopy(ctx))
        except Exception as e:
            log.warning('%s: failed to init - %s' % (team_name, e))

    if not team_ctxs:
        log.error('No teams could be initialized')
        return 1

    team_queues = {}
    stop_event = threading.Event()

    for team_name, (ioctx, ctx) in team_ctxs.items():
        q = queue.Queue()
        team_queues[team_name] = q
        t = threading.Thread(
            target=_team_worker,
            args=(team_name, ioctx, ctx, exploit, config, args, flag_format, flag_storage, flagid_storage, q, stop_event),
            daemon=True,
        )
        t.start()

    try:
        for attack_no in once_in_a_period(args.period):
            try:
                data = get_flagids(args, config.challname)
                flagid_storage.update(config.challname, data)
                log.info('Fetched flag IDs for %d teams' % len(data))
            except Exception as e:
                log.warning("Can't fetch flag IDs: %s" % e)
                log.warning('No flag id for attack #%d' % attack_no)

            log.info('Launching attack #%d on %d teams' % (attack_no, len(team_ctxs)))

            post_stop = threading.Event()
            post_thread = threading.Thread(
                target=_post_loop, args=(args, flag_storage, post_stop), daemon=True
            )
            post_thread.start()

            for q in team_queues.values():
                q.put(args.period)

            for q in team_queues.values():
                q.join()

            post_stop.set()
            post_thread.join()

    except KeyboardInterrupt:
        log.info('Got Ctrl+C, shutting down')

    stop_event.set()
    exit_event.set()
    return 0
