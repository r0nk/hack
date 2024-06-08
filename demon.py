#!/bin/env python3
import pathlib
from os import listdir
import os
import sys
import inotify.adapters
import re
import subprocess
import xml.etree.ElementTree as ET

handlers = []

self_path=sys.argv[0]

# Define regex patterns
ipv4_pattern = re.compile(r'^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$')
ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$')
port_pattern = re.compile(r'^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$')

def is_valid_ipv4(ip):
    return bool(ipv4_pattern.match(ip))

def is_valid_ipv6(ip):
    return bool(ipv6_pattern.match(ip))

cwd = pathlib.Path().absolute()
print(cwd)

ip_address=''

for part in cwd.parts:
    if(is_valid_ipv4(part)):
        ip_address=part

# read local information
print(listdir(cwd))

def split(path):
    try:
        os.mkdir(path)
    except OSError as error:
        print(f"skipping split {path}, already exists.")
        return
    subprocess.Popen(["../"+self_path],cwd=path)

def todo(name,time_est=60):
    with open("todo.txt", 'a') as file:
        file.write(f"{name} {time_est}")

def parse_nmap_xml_split(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall('host'):
        ip_address = host.find('address').attrib['addr']
        print(f"IP Address: {ip_address}")

        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                port_id = port.attrib['portid']
                protocol = port.attrib['protocol']
                state = port.find('state').attrib['state']
                split(port_id)

def parse_nmap_xml_single(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall('host'):
        ip_address = host.find('address').attrib['addr']
        print(f"IP Address: {ip_address}")

        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                state = port.find('state').attrib['state']
                service = port.find('service').attrib['name']
                with open("service.txt", 'a') as file:
                    file.write(f"{service}")


def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.findall('host'):
        ip_address = host.find('address').attrib['addr']
        print(f"IP Address: {ip_address}")

        for ports in host.findall('ports'):
            for port in ports.findall('port'):
                port_id = port.attrib['portid']
                #split(port_id)
                protocol = port.attrib['protocol']
                state = port.find('state').attrib['state']
                service = port.find('service').attrib['name']

                print(f"  Port: {port_id}/{protocol}, State: {state}, Service: {service}")


def ip_handler():
    if(is_valid_ipv4(cwd.name)):
        split('tcp')
        split('udp')
        return True
    return False
handlers.append(ip_handler)

def tcp_handler():
    if(cwd.name == 'tcp'):
        subprocess.run(f"nmap -oX nmap.xml {ip_address}",shell=True)
        parse_nmap_xml_split("nmap.xml")
        subprocess.run(f"nmap -p- -oX nmap_full.xml {ip_address}",shell=True)
        parse_nmap_xml_split("nmap_full.xml")
        return True
    return False
handlers.append(tcp_handler)

def udp_handler():
    if(cwd.name == 'udp'):
        todo("nmap")
        return True
    return False
handlers.append(udp_handler)

def unidentified_port_handler():
    if os.path.isfile('service.txt')
        return False #already handled
    port=cwd.name
    #check that the parents are something like /tcp/1234/
    subprocess.run(f"nmap -p {port} -sC -sV -oX nmap.xml {ip_address}",shell=True)
    parse_nmap_xml_single("nmap.xml")
handlers.append(unidentified_port_handler())

def handle():
    for h in handlers:
        print("trying",h.__name__)
        handled=h()
        print(h.__name__,handled)
        if (handled): return True
    return False

handle()
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
