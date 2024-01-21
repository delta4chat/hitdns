#!/usr/bin/python3
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
            pkg, ver = line['package_id'].split(' ')[:2]
            yield (pkg, ver)
        line = process.stdout.readline()

def deps():
    dep = {}
    for pkg, ver in _deps():
        if pkg not in dep:
            dep[pkg] = set()
        
        dep[pkg].add(ver)

    return dep

def duplicated_deps():
    dep = {}
    for pkg, vers in deps().items():
        if len(vers) > 1:
            dep[pkg] = vers

    return dep

ml = 0
dep = duplicated_deps()
for pkg in dep:
    l = len(pkg)
    if l > ml:
        ml = l

for pkg, vers in dep.items():
    print('[', pkg, '] =', sep='')
    print(' '*(ml+3), repr(vers))
    print('='*(ml*3), os.linesep)
