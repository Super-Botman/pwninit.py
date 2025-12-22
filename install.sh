#!/bin/sh

python3 -m build
pipx install ./dist/pwninit-0.0.1-py3-none-any.whl --force
