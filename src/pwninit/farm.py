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

# --- thread-local proxy for io.ioctx ---
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
# ---------------------------------------

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
    return {'Authorization': args.password}


def get_farm_config(args):
    url = urljoin(args.url, '/api/get_config')
    r = requests.get(url, headers=get_auth_headers(args), timeout=SERVER_TIMEOUT)
    if not r.ok:
        raise Exception(r.text)
    return r.json()


def post_flags(args, flags):
    sploit_name = Path('exploit.py').resolve().parent.name
    data = [{'flag': item['flag'], 'sploit': sploit_name, 'team': item['team']}
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


def _run_one(exploit, ioctx, ctx, team_name, max_runtime, flag_format, flag_storage):
    try:
        ioctx.connect(log=False)
    except Exception as e:
        log.warning('%s: connection failed - %s' % (team_name, e))
        return

    ioctx.conn.timeout = max_runtime

    try:
        result = exploit(ctx, ioctx)
        flags = flag_format.findall(result) if isinstance(result, (str, bytes)) else []
        if not flags and result:
            flags = [result]
        for flag in flags:
            log.success('%s: got flag %s' % (team_name, flag))
            flag_storage.add(flag, team_name)

        ioctx.close(log=False)
    except Exception as e:
        log.warning('%s: exploit failed - %s' % (team_name, e))


def _team_worker(team_name, ioctx, ctx, exploit, flag_format, flag_storage, task_queue, stop_event):
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

        try:
            _run_one(exploit, ioctx, ctx, team_name, max_runtime, flag_format, flag_storage)
        finally:
            task_queue.task_done()


def run_farm(args, config, exploit):
    from pwninit.helpers import PwnContext

    log.info('Connecting to farm server at %s' % args.url)

    try:
        farm_config = get_farm_config(args)
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

    team_ctxs = {}
    for team_name, team_addr in teams.items():
        try:
            team_args = copy.copy(args)
            team_args.remote.host = team_addr
            ioctx = IOContext(team_args, config)
            ctx = PwnContext(ioctx.proc, config.binary, config.libc)
            team_ctxs[team_name] = (ioctx, ctx)
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
            args=(team_name, ioctx, ctx, exploit, flag_format, flag_storage, q, stop_event),
            daemon=True,
        )
        t.start()

    try:
        for attack_no in once_in_a_period(args.period):
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
