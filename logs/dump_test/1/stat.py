import pandas as pd

elpus = pd.read_csv('eprocess_lpusscan.csv')
flpus = pd.read_csv('file_lpusscan.csv', encoding='utf-8')

evol = pd.read_csv('eprocess_volscan.csv')
fvol = pd.read_csv('file_volscan.csv')

print('''
A simple statistics for LPUS and Volatility

Environment: Windows 10 2019 (build number 18362) on VirtualBox
RAM: 4GB

> The VM is downloaded through Microsoft

LPUS scan _EPROCESS and _FILE_OBJECT.
The scan time: approximate 5 minutes.

After that, use VirtualBox command to generate the memory image

> "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "<name>" dumpvmcore --filename "/path/to/<name>.elf"

Volatility version is at 5f685e5

> The latest release of Volatility doesn't have support for Windows build no. 18362

Then compare the log from LPUS and the two volatility command with profile Win10x64_18362:
- psscan to scan _EPROCESS, approximate 30 minutes
- filescan to scan _EPROCESS, approximate 2-3 hours

(The log file is then converted to csv files, see 'eprocess_to_csv.py' and 'file_to_csv.py')

''')

print('==================================================')

print('_EPROCESS')
print('lpus scan: ', elpus['address'].shape, 'results')
print('volatility scan: ', evol['address'].shape, 'results')
print('volatility scan misses lpus: ', elpus['address'][~elpus['address'].isin(evol['address'])].shape, 'results')
print('lpus scan misses volatility: ', evol['address'][~evol['address'].isin(elpus['address'])].shape, 'results')

print('==================================================')

print('_FILE_OBJECT')
print('lpus scan: ', flpus['address'].shape, 'results')
print('volatility scan: ', fvol['address'].shape, 'results')
print('volatility scan misses lpus: ', flpus['address'][~flpus['address'].isin(fvol['address'])].shape, 'results')
print('lpus scan misses volatility: ', fvol['address'][~fvol['address'].isin(flpus['address'])].shape, 'results')
