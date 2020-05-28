import sys
import re

s = list(filter(lambda x: "unicode" in x, open(sys.argv[1], 'r').read().split('\n')))


m = re.compile(r"unicode str: (0x[0-9a-f]+) size: (0x[0-9a-f]+) capacity: (0x[0-9a-f]+)")

ss = list(filter(lambda x: int(x[0], 16) != 0 and int(x[1], 16) <= int(x[2], 16) and int(x[1], 16) != 0 and int(x[1], 16) % 2 == 0,
                 map(lambda x: m.match(x).group(1,2,3), s)))

aa = set()
bb = set()

for (a, s, c) in ss:
    if a in aa or a in bb:
        continue
    aa.add(a)
    # print("du", a, "|", s, c)
    print("du", a)
