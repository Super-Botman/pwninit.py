#!/bin/sh

python3 -m build
mv ./dist/pwninit-0.0.1-py3-none-any.whl ./dist/pwninit
pipx install ./dist/pwninit --force

