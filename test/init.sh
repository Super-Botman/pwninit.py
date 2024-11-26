#!/usr/bin/env bash

find ~/Documents/challenges -type f -executable -exec file -i '{}' \; | grep "application/.*; charset=binary" | cut -f1 -d":" > files.txt
