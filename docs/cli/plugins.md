# Plugin Development Guide

This guide explains how to extend `pwninit` using custom plugins. Plugins allow you to register custom actions under two lifecycle roles: **providing** challenge assets (e.g., fetching files over network targets) and **setting up** target environments (e.g., adding customization templates or Docker dependencies).

---

## Architecture Lifecycle

The `pwninit` plugin manager automatically loads python scripts from your configuration folder at `~/.config/pwninit/plugins/`.

When designing your plugin, you can choose to implement either one or both functional methods depending on where you want to hook into the runtime lifecycle:

1. **`provide(self, args, path)`**: Executes _first_. It handles asset ingestion. The framework passes the current working directory `Path` as its environment argument.
2. **`setup(self, args, bins)`**: Executes _last_ (after binaries are sorted, patched, and Docker containers build). The framework passes the parsed `sorted_bins` dictionary as its environment argument.

---

## Core Plugin API Template

Every custom extension must expose a class exactly named `Plugin` inheriting from the base architecture. Command-line flags are configured via list arrays using the helper utility `arg()`.

Here is the exact developer blueprint for a clean, minimal plugin:

```python
from pwninit.plugins import Plugin, arg
from pwn import log

class Plugin(Plugin):
    name = "my_plugin"
    description = "A clean minimal blueprint for custom pwninit plugins."

    # Define CLI parameters parsing rules for 'pwninit -p my_plugin ...'
    provide_args = [
        arg("target_id", help="An implicit positional parameter"),
        arg("--force", help="Toggle operational behavior modifiers", action="store_true")
    ]

    # Define CLI parameters parsing rules for 'pwninit -s my_plugin ...'
    setup_args = [
        arg("--port", help="Network tracking port setup override", default="1337")
    ]

    def provide(self, args, path):
        """Executed during the asset provisioning phase.

        Args:
            args: An argparse Namespace containing validated variables.
            path (Path): A pathlib.Path object pointing to the output directory workspace.

        Returns:
            Path: The directory containing your new challenge files. If a custom Path
                  is returned, pwninit pivots its binary analysis lookup to that folder!
        """
        log.info(f"[{self.name}] Fetching assets for target: {args.target_id}")

        # Implement custom file generation, network requests, or downloads here.

        return path

    def setup(self, args, bins):
        """Executed during the final environment/utility initialization step.

        Args:
            args: An argparse Namespace containing validated variables.
            bins (dict): A dictionary populated with sorted file mappings:
                         {"libc": [...], "ld": [...], "challs": [...], "libs": [...]}

        Returns:
            dict: Key/Value pairs of file names and string contents.
                  pwninit will automatically write these out as output files!
        """
        log.info(f"[{self.name}] Initializing post-patch system adjustments on port: {args.port}")

        extra_output_files = {}

        if bins.get("challs"):
            target_binary = bins["challs"][0]
            log.info(f"[{self.name}] Hooking configurations into target: {target_binary}")

            # Example: Generating a localized runner or configuration block
            extra_output_files["gdb_script.ini"] = f"file {target_binary}\nb target remote :{args.port}\n"

        return extra_output_files

```

---

## Argument Format Configurations

The `arg(name, kwargs)` decorator mirrors parameters directly into the initialization layer of Python’s standard `argparse.ArgumentParser.add_argument` engine.

### Common Mappings Cheat-Sheet:

- **Positionals**: `arg("variable_name", help="...")`
- **Optional Flags**: `arg("--force", action="store_true")`
- **Strict Options Selector**: `arg("--arch", choices=["x86", "amd64"], default="amd64")`
- **Typed Input Parsing**: `arg("--timeout", type=int, default=30)`

---

## Deploying and Running Extensions

To activate your script, place your file directly inside your user configuration workspace directory:

```bash
mkdir -p ~/.config/pwninit/plugins/
cp my_plugin.py ~/.config/pwninit/plugins/

```

### Discovery and Execution Syntax

To print out a structural overview of all locally resolved plugin commands:

```bash
pwninit --list-plugins

```

To run your plugin as an automated asset downloader component:

```bash
pwninit -p my_plugin "CHALLENGE_01" --force

```

To run your plugin as a post-processing scaffolding environment engine:

```bash
pwninit -s my_plugin --port 4444

```
