import re
import csv

vp = re.compile(r'^(0x[0-9a-f]+)\s+(.{15})\s+\d+\s+\d+.*$')

vol = map(lambda x: x.group(1, 2), filter(lambda x: x is not None, map(vp.match, open('eprocess_volscan.txt', 'r').read().split('\n'))))

with open('eprocess_volscan.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['address', 'process'])
    for v in vol:
        a, b = list(v)
        a = hex(int(a, 16) + 0xffff000000000000)
        b = b.rstrip(' ')
        writer.writerow([a, b])


# lp = re.compile(r'pool: 0x[0-9a-f]+ \| file object: (0x[0-9a-f]+) \| offsetby: 0x[0-9a-f]+\s+(.*)$', re.MULTILINE)

lpus = re.finditer(r'pool: 0x[0-9a-f]+ \| eprocess: (0x[0-9a-f]+) \| ([^|]*) \| (.*)$',
                   open('eprocess_scan_log.txt', 'r', encoding='utf-8').read(), re.MULTILINE)

with open('eprocess_lpusscan.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['address', 'process', 'fullpath'])
    for v in lpus:
        a, b, c = list(v.groups())
        writer.writerow([a, c, b])

