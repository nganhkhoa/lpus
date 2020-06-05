import re
import csv

vp = re.compile(r'(0x[0-9a-f]+)\s+\d+\s+[01]\s+[RWDrwd-]+\s+(.*)')

vol = map(lambda x: x.group(1, 2), filter(lambda x: x is not None, map(vp.match, open('file_volscan.txt', 'r').read().split('\n'))))

with open('file_volscan.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['address', 'file'])
    for v in vol:
        a, b = list(v)
        a = hex(int(a, 16) + 0xffff000000000000)
        writer.writerow([a, b])


# lp = re.compile(r'pool: 0x[0-9a-f]+ \| file object: (0x[0-9a-f]+) \| offsetby: 0x[0-9a-f]+\s+(.*)$', re.MULTILINE)

lpus = map(lambda x: x.group(1, 2), filter(lambda x: x is not None, map(vp.match, open('file_volscan.txt', 'r').read().split('\n'))))

lpus = re.finditer(r'pool: 0x[0-9a-f]+ \| file object: (0x[0-9a-f]+) \| offsetby: 0x[0-9a-f]+\s+(.*)$',
                   open('file_scan_log.txt', 'r', encoding='utf-8').read(), re.MULTILINE)

with open('file_lpusscan.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['address', 'file'])
    for v in lpus:
        a, b = list(v.groups())
        writer.writerow([a, b])
