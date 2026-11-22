# DPI Engine (Java)

A Deep Packet Inspection (DPI) project written in Java.

It reads a network capture file (.pcap), finds out which website or app each
connection belongs to, blocks the ones you choose, and saves the rest to a new file.

## What it does
- Reads packets from a .pcap file
- Detects apps like YouTube, Facebook, Netflix and TikTok
- Blocks traffic by app, IP address or domain
- Shows a report with total, forwarded and dropped packets

## How it works
HTTPS is encrypted, but the website name is visible in the first packet of the
connection (called SNI). The program reads that name, finds the app, and
applies the blocking rules.

## Requirements
Java 17 or newer

## How to run
```
java -jar dpi-engine.jar samples/test_dpi.pcap output.pcap
```

## How to block
```
java -jar dpi-engine.jar samples/test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
```

| Option | Meaning |
|---|---|
| --block-app | Block an app (YouTube, Facebook, ...) |
| --block-ip | Block a source IP address |
| --block-domain | Block a domain name |
| --single | Run in single-threaded mode |

## Sample result
The sample file has 77 packets. Blocking YouTube and 192.168.1.50 forwards 71
and drops 6.


## Author
Arti Rawat
