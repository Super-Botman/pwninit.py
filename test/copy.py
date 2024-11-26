import os

file = open("files.txt", "r")

for line in file.readlines():
    os.system('cp "%s" ./bins' % line[:-1])
