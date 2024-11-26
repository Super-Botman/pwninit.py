#!/usr/bin/env python3

from pwn import *
import re

sys.path.insert(0, './')
from exploit import CHALL

io = process(CHALL)
functions = []
menu = io.recv(timeout=0.2).replace(b'\x00', b'').split(b'\n')
menu = [ l for l in menu if l ]
space_count = len(menu[-1].split(b' '))
prefix = re.sub('[A-Za-z]', '', menu[-1].decode())[space_count-2:]

menu_title = menu[0].decode()
variable_len = 2

for line in menu:
    if len(line) == 0:
        continue

    line = line.decode().lower()
    if line[0].isdigit():
        function_name = '_'.join(line.split(' ')[1:])
        input = line[0]
        functions.append([input, function_name, []])

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
            content = content.decode().replace('\x00', '').split('\n')
        except EOFError:
            eof = True
            break

        content = [ l for l in content if l ]
        if menu_title in content:
            break

        submenu = content[-1]

        input_type = "%s"
        if '[' in submenu and ']' in submenu:
            input_type = "str(%s).encode()"
            io.sendline(b'0')
        else:
            submenu = submenu.replace(prefix, '')
            io.sendline(b'')

        submenu = re.sub('\[.*\]', '', submenu)
        submenu = submenu.split(' ')[1:-1][:variable_len]
        name = '_'.join([ l for l in submenu if l ]).lower()

        submenus.append([name, input_type])

    functions[i][2] = submenus

code = 'PREFIX = b\'%s\'\n' % prefix
for function in functions:
    if len(function[2]) > 0:
        code += '\n\ndef %s(%s, io):\n' % (function[1], ', '.join([ f[0] for f in function[2] ]))
    else:
        code += '\n\ndef %s(io):\n' % function[1]

    code += '   io.sendlineafter(PREFIX, b\'%s\')\n' % function[0]

    if len(function[2]) > 0:
        for submenu, submenu_type in function[2]:
            to_send = submenu_type % submenu
            code += '   io.sendlineafter(PREFIX, %s)\n' % to_send
    
    code += '   return io.recvline()\n'

open('exploit.py', 'a').write(code)
