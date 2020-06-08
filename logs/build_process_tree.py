import sys
import re
import collections

class Process:
    def __init__(self, e, pid, ppid, name, path):
        self.e = e
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.path = path
    def __str__(self):
        return f'{self.e} {self.pid} {self.ppid} {self.name} {self.path}'
    def __repr__(self):
        return f'{self.e} {self.pid} {self.ppid} {self.name} {self.path}'

process_map = {}

# shamelessly steal from https://github.com/giampaolo/psutil/blob/master/scripts/pstree.py
# not work if a detached node presents
def print_tree(parent, tree, indent='', traversed=[]):
    try:
        p = process_map[parent]
        name = f"{p.pid} [{p.name}] {p.path}"
    except:
        name = f"{parent} [UNNOWN]"
    # input(name)
    if parent in traversed:
        print(name, "[LOOP]")
        return
    else:
        print(name)
    traversed += [parent]

    if parent not in tree:
        return
    children = tree[parent][:-1]
    for child in children:
        print(indent + "|- ", end='')
        print_tree(child.pid, tree, indent + "| ", traversed)
    child = tree[parent][-1]
    print(indent + "`_ ", end='')
    print_tree(child.pid, tree, indent + "  ", traversed)

lpus = re.finditer(r'^pool: 0x[0-9a-f]+ \| eprocess: (0x[0-9a-f]+) \| pid: (\d+) \| ppid: (\d+) \| name: ([^|]*) \| (.*)$',
                   open(sys.argv[1], 'r', encoding='utf-8').read(), re.MULTILINE)

process_tree = {}
for v in lpus:
    e, pid, ppid, name, path = list(v.groups())
    proc = Process(e, int(pid), int(ppid), name, path)
    process_map[int(pid)] = proc
    if int(ppid) in process_tree:
        process_tree[int(ppid)] += [proc]
    else:
        process_tree[int(ppid)] = [proc]

if 0 in process_tree:
        process_tree.pop(0)

remove = []
for k, child in process_tree.items():
    for c in child:
        if c.pid in process_tree and c.ppid in process_tree:
            # print('remove', c)
            remove += [c.pid]
            break

# print(remove)
for k in process_tree.keys():
    if k not in remove:
        print_tree(k, process_tree)
        # input()

