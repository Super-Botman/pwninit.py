#!/bin/sh

python3 -m build
pipx install ./dist/*.whl --force
