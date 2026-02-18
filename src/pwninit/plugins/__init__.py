from pickle import BUILD
import argparse
import importlib
import importlib.util
import sys
from pwn import log
from pathlib import Path

PLUGIN_DIR = Path.home() / ".config" / "pwninit" / "plugins"

class Plugin:
    name = None
    description = ""
    provide_args = []
    setup_args = []

    def provide(self, args, path): raise NotImplementedError
    def setup(self, args, bins): raise NotImplementedError

    @property
    def has_provide(self):
        return type(self).provide is not Plugin.provide

    @property
    def has_setup(self):
        return type(self).setup is not Plugin.setup

def arg(name, **kwargs):
    return {"name": name, **kwargs}

def _load_plugin(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        log.warning("Failed to load plugin %s: %s" % (path, e))
        return None
    return mod

def _resolve(name):
    plugin = PLUGIN_DIR / f"{name}.py"
    if plugin.is_file():
        mod = _load_plugin(name, plugin)
        if mod:
            return mod.Plugin()

    try:
        mod = importlib.import_module(f"pwninit.plugins.{name}")
        return mod.Plugin()
    except ModuleNotFoundError:
        pass

    return None

def _parse_plugin_args(plugin, raw_args, role):
    arg_list = plugin.provide_args if role == "provide" else plugin.setup_args

    parser = argparse.ArgumentParser(
        prog=plugin.name,
        description=plugin.description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    for a in arg_list:
        a = dict(a)
        n = a.pop("name")
        short = a.pop("short", None)
        names = [short, n] if short else [n]
        parser.add_argument(*names, **a)

    try:
        return parser.parse_args(raw_args)
    except SystemExit:
        return None


def run_plugins(args, role, settings):
    plugin = _resolve(args[0])
    if plugin is None:
        log.error("Plugin '%s' not found" % args[0])
        return None

    parsed = _parse_plugin_args(plugin, args[1], role)
    if parsed is None:
        return None

    if role == "provide" and plugin.has_provide:
        return plugin.provide(parsed, settings)
    elif role == "setup" and plugin.has_setup:
        return plugin.setup(parsed, settings)
    else:
        log.error("Plugin '%s' has no %s()" % (args[0], role))
        return None

def _get_infos(dir, source="built-in"):
    seen = {}
    for f in sorted(dir.glob("*.py")):
        if f.name.startswith("_"):
            continue
        name = f.stem
        mod = _load_plugin(name, f)
        if mod is None:
            continue
        plugin = mod.Plugin()
        roles = []
        if plugin.has_provide:
            roles.append("provider")
        if plugin.has_setup:
            roles.append("utility")
        if not roles:
            continue
        seen[name] = plugin, roles, source
    return seen

def _list_plugins():
    seen = {}

    builtin = Path(__file__).parent
    if builtin.is_dir():
        seen.update(_get_infos(builtin, "built-in"))

    # external overrides built-in
    if PLUGIN_DIR.is_dir():
        seen.update(_get_infos(PLUGIN_DIR, "external"))

    return seen

def _format_arg(a):
    a = dict(a)
    name = a.get("name", "?")
    help_text = a.get("help", "")
    default = a.get("default", None)
    choices = a.get("choices", None)

    parts = name
    if choices:
        parts += " {%s}" % "|".join(str(c) for c in choices)
    if default is not None:
        parts += " (default: %s)" % default
    if help_text:
        parts += " - %s" % help_text
    return parts

def _build_parser(plugin, role):
    arg_list = plugin.provide_args if role == "provide" else plugin.setup_args
    flag = "-p" if role == "provide" else "-u"

    parser = argparse.ArgumentParser(
        prog="pwninit %s %s" % (flag, plugin.name),
        description=plugin.description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    for a in arg_list:
        a = dict(a)
        n = a.pop("name")
        short = a.pop("short", None)
        names = [short, n] if short else [n]
        parser.add_argument(*names, **a)
    return parser

def _format_arg(a):
    a = dict(a)
    name = a.get("name", "?")
    short = a.get("short", "")
    help_text = a.get("help", "")
    default = a.get("default", None)

    label = "%s, %s" % (short, name) if short else name
    parts = "%-20s" % label
    if help_text:
        parts += " %s" % help_text
    if default is not None:
        parts += " (default: %s)" % default
    return parts

def print_plugin_list():
    plugins = _list_plugins()
    if not plugins:
        log.info("No plugins found")
        return

    items = list(plugins.items())
    for i, (name, (plugin, roles, source)) in enumerate(items):
        print(f"{name}: {plugin.description}")

        if "provider" in roles:
            _build_parser(plugin, "provide").print_usage()
            for a in plugin.provide_args:
                print("      %s" % _format_arg(a))
            print()

        if "utility" in roles:
            _build_parser(plugin, "setup").print_usage()
            for a in plugin.setup_args:
                print("      %s" % _format_arg(a))
            print()

        if i < len(items) - 1:
            print(" " * 20 + "─" * 20)
