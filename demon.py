import pathlib
from os import listdir
import inotify.adapters
import re
import subprocess

handlers = []

# Define regex patterns
ipv4_pattern = re.compile(r'^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$')
ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$')

def is_valid_ipv4(ip):
    return bool(ipv4_pattern.match(ip))

def is_valid_ipv6(ip):
    return bool(ipv6_pattern.match(ip))

cwd = pathlib.Path().absolute()
print(cwd)

# read local information
print(listdir(cwd))

def split(path):
    os.mkdir(path)
    subprocess.Popen(["demon.py"],cwd=path)

def todo(name,time_est=60):
    with open("todo.txt", 'a') as file:
        file.write(f"{name} {time_est}")


def ip_handler():
    if(is_valid_ipv4(cwd.name)):
        split('tcp')
        split('udp')
handlers.append(ip_handler)

def tcp_handler():
    todo("nmap")

def udp_handler():
    todo("nmap")

handlers.append(tcp_handler)

def handle():
    for h in handlers:
        if (h()): return True
    return false

i = inotify.adapters.Inotify()
i.add_watch(str(cwd))
while True:
    for event in i.event_gen():
        if not event: #wtf?
            continue
        if( event[1][0] != 'IN_CLOSE_WRITE'):
            continue
        print(event[1][0])
        handle()
        break #dont run multiple handles if the events happen right beside each other.
