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

cwd = pathlib.Path().absolute()
print(cwd)



def handle():
    for h in handlers:
        print("trying",h.__name__)
        handled=h()
        print(h.__name__,handled)
        if (handled): return True
    return False

def main():
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

if __name__=="__main__":
    main()
