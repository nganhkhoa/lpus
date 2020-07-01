
windows_epoch_diff = 11644473600000 * 10000
filetime = 132380977838542980

process_time_epoch = (filetime - windows_epoch_diff) // 10000
print(process_time_epoch)

