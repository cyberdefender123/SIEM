# SIEM

## README for Python SIEM Project
Build a SIEM using python and mySQL server

Using python to build a customised SIEM. SIEM can read firewall logs and logs sniffed by python (scapy) in real-time.

## Prerequisites:
##### Ubuntu Linux Server 1604 with mySQL
##### Python

## Python Scripts:
#### Sniffer.py
Uses Scapy to sniff the interface and continuously writes logs into a log file.

#### Parser.py
SIEM database is built on the Ubuntu Server and logs are first converted into the correct format and then parsed from the log file into the database in real-time. 
Format required - 
DATETIME  -  SOURCE_IP  -  DEST_IP  -  PORT  -  ACTION

#### Analyser.py
Analyses the logs in the database and sends an alert for specific attacks: a specific port contacted, a port scan of more than 10 ports from same source ip, a ping sweep and a ping sweep in less than 10 seconds. The analyser is set to run automatically every 5 seconds, checking for new attacks.

## Log Files:
##### ScapyLogs.txt - log file of incoming and outgoing packets in the interface, live updated.
##### Port_Scan.txt - firewall log containing a port scan.
##### Ping_Sweep.txt - firewall log containing a ping sweep.

