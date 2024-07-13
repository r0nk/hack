#!/bin/env python3

import xml.etree.ElementTree as ET
import os.path

def split(path):
    try:
        os.mkdir(path)
    except OSError as error:
        print(f"skipping split {path}, already exists.")
        return


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

def conditions():
    return ((cwd.name == 'tcp') and not os.path.isfile("nmap.xml") and not os.path.isfile("nmap_full.xml"))

def tcp_handler():
    if( not conditions()):
        return False
    subprocess.run(f"nmap -oX nmap.xml {ip_address}",shell=True)
    parse_nmap_xml_split("nmap.xml")
    subprocess.run(f"nmap -sV -sC -p- -oX nmap_full.xml {ip_address}",shell=True)
    parse_nmap_xml_split("nmap_full.xml")
    return True

tcp_handler()
