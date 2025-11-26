from pwn import process, context, STDOUT
from mako.template import Template
from pathlib import Path
import os
import re


def create_menu(functions, io, menu_title, prefix, variable_len):
    eof = False
    for i in range(len(functions)):
        if eof:
            break

        function = functions[i]
        io.sendline(function[0].encode())

        submenus = []
        while not eof:
            try:
                content = io.recvuntil(prefix.encode())
                content = content.decode().replace("\x00", "").split("\n")
            except EOFError:
                eof = True
                break

            content = [l for l in content if l]
            if menu_title in content:
                break

            submenu = content[-1]

            input_type = "%s"
            if "[" in submenu and "]" in submenu:
                input_type = "str(%s).encode()"
                io.sendline(b"0")
            else:
                submenu = submenu.replace(prefix, "")
                io.sendline(b"")

            submenu = re.sub(r"\[.*\]", "", submenu)
            submenu = submenu.split(" ")[1:-1][:variable_len]
            name = "_".join([l for l in submenu if l]).lower()

            submenus.append([name, input_type])

        functions[i][2] = submenus

    return functions


def build_exploit(menu, files, prefix, bins):
    # Build menu functions as a string
    menu_code = f'PREFIX = b"{prefix}"\n'

    for function in menu:
        if len(function[2]) > 0:
            menu_code += "\n\ndef %s(%s, io):\n" % (
                function[1],
                ", ".join([f[0] for f in function[2]]),
            )
        else:
            menu_code += "\n\ndef %s(io):\n" % function[1]

        menu_code += "   io.sendlineafter(PREFIX, b'%s')\n" % function[0]

        if len(function[2]) > 0:
            for submenu, submenu_type in function[2]:
                to_send = submenu_type % submenu
                menu_code += "   io.sendlineafter(PREFIX, %s)\n" % to_send

        menu_code += "   return io.recvline()\n"

    # Re-render the template with menu functions included
    pwninit_path = Path(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    templates = pwninit_path / "templates"
    exploit_template = Template(filename=str(templates / "exploit.py"))

    files["exploit.py"] = exploit_template.render(
        chall="./" + os.path.basename(bins["challs"][0]),
        libc="./" + os.path.basename(bins["libc"][0]) if bins["libc"] else None,
        menu_functions=menu_code,
    )

    return files


def run(files, bins, path):
    io = process([bins["challs"][0], "2>&1"], shell=True)
    functions = []
    menu = io.recvlines(20, timeout=1)
    menu = [l for l in menu if l]
    space_count = len(menu[-1].split(b" "))
    prefix = re.sub("[A-Za-z]", "", menu[-1].decode())[space_count - 2 :]

    menu_title = menu[0].decode()
    menu = menu[1:]
    variable_len = 2

    for line in menu:
        if len(line) == 0:
            continue

        line = line.decode().lower()
        if re.findall(r"[0-9]", line):
            print(line.split(" "))
            function_name = "_".join([l for l in line.split(" ")[1:] if l])
            input = re.findall(r"[0-9]", line)[0]
            functions.append([input, function_name, []])

    menu = create_menu(functions, io, menu_title, prefix, variable_len)
    return build_exploit(menu, files, prefix, bins)
