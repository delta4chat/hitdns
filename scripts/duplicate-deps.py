#!/bin/env python3

import sys

import subprocess
import json
import os

def _deps():
    process = subprocess.Popen(['cargo', 'check', '--message-format=json'], stdin=None, stdout=subprocess.PIPE, stderr=None)
    decoder = json.JSONDecoder()
    line = process.stdout.readline()
    while len(line) > 0:
        line = line.decode('utf-8')
        line = decoder.scan_once(line, 0)[0]
        if line['reason'] == 'compiler-artifact':
            print(line, file=sys.stderr)
            try:
                pkg, ver = line['package_id'].split('#')[-1].split('@')
            except Exception as err:
                print(repr(err), file=sys.stderr)
            else:
                yield (pkg, ver)
        line = process.stdout.readline()

def deps():
    dep = {}
    for pkg, ver in _deps():
        if pkg not in dep:
            dep[pkg] = set()
        
        dep[pkg].add(ver)

    return dep

def str2int(s):
    return int((b'\xff' + s.encode()).hex(), 16)

def duplicated_deps():
    dep = deps()
    for pkg in sorted(dep.keys(), key=str2int):
        vers = dep[pkg]
        if len(vers) > 1:
            yield (pkg, sorted(vers, key=str2int))

ml = 16
dep = list(duplicated_deps())
#for pkg, _ in dep:
#    l = len(pkg)
#    if l > ml:
#        ml = l

for pkg, vers in dep:
    print('[', pkg, '] =', sep='')
    print(' '*(ml+3), ' | '.join(vers))
    print('='*(ml*3), os.linesep)
