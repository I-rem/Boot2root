writeup2.md

https://github.com/safebuffer/PE-Linux/blob/master/PE.sh

`zaz@BornToSecHackMe:~$ vim PE.sh`
`zaz@BornToSecHackMe:~$ chmod 777 PE.sh`
`zaz@BornToSecHackMe:~$ ./PE.sh`

```
./PE.sh: line 1: cript: command not found






############# PE Linux        
############# By WazeHell     
############# Reporting Directory : /Report 
#########################################################
#################### System Info ########################
#########################################################
Kernel : 3.2.0-91-generic-pae
#########################################################
Hostname: BornToSecHackMe
#########################################################
Linux kernel architecture: i686
#########################################################
Full Kernel information:
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux
#########################################################
Distribution information:
"Ubuntu 12.04.5 LTS"
#########################################################
More About Kernel:
  GCC stack protector support:            Disabled
  Strict user copy checks:                Disabled
  Enforce read-only kernel data:          Disabled
  Restrict /dev/mem access:               Disabled
  Restrict /dev/kmem access:              Enabled
#########################################################
Programming Langage in the system:
perl
gcc
python
php
cc
#########################################################
Environment information:
#########################################################
Check Environment.txt
#########################################################
Path information:
Check PATH.txt
#########################################################
Checking DirtyCoW Exploit :
MoW You Are Need A Cow !! 
#########################################################
################# Passwords Lookup ######################
#########################################################
#########################################################
umask value as specified in /etc/login.defs:
UMASK           022
#########################################################
Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512
#########################################################
Possible Passwords in Files:
Check Passwords.txt File For Possible Scripts Have A Passwords
#########################################################
Files Maybe Cabiton Passwords (configs):
Check passwordfiles.txt
#########################################################
 There No SSH With Root :( 
#########################################################
 We Found Some RSA Keys :) 
 ssh-dss AAAAB3NzaC1kc3MAAACBANy4kCYLoBAylTLMh64JVr40/F9bciwyI6xUYNGxwUcQSZO4isexdm9EmOGxstbAs2Hcfq9JssaCGBX/gAENQ6+0fI7AYhM2H0UmzITyd/xd8LYljaLeE6qIyfM/1Enjbl04FMsK4FvYr94Dz2ucWLraIrv+mKO8kqN8nR5CXbpxAAAAFQDjJ8bghJac5CEvsPfVXq41Zq03lwAAAIB03IhWaPcHl5FLycI6/jhANgwyk5sIRPmAy2BoQ0pGnZjEaRIz5XRW7uNM4WScbZ6J9Ztk48KDqS/RaWpHzOxolx3xfIaoOJeNv8SyUPleK/+JcJTSX8hVsijQ91W+U9GiMPGlZLWy5uzDt+v4Pfagor7KQuMR7RDMA/CASfwYUAAAAIAL6FIxFwQFgzpslh0KjjKCeZ7EFTrbdIzp8NDGzfA9zXb/znT67oAClH6sVZCjqPQHwE/+4FIw0ek5Bec8fEXuqUDWQvkePUaKaMVnN2SnTMB1TG2I5UbrigrEFMudWzqVZBdb1eH44UrdPhDC3HR94pmM7ppL82elMAqK4XSNgQ== root@ubuntu 
#########################################################
 We Found Some RSA Keys :) 
 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4oEueIHc1nDjKzt/MI7Wz8sQi13IZQZuG6FtaK6aBxkTztoBLLqSitQ6y2zB+kEdc9BJTCU2utolXic/JfcBwWJyMi0JDBAXdgctpx4JB731cxHntCldMMOlDdaw57GfdXQVqJLC0ev8o6ADqJCK3tgcP9lJKrbVVS+LmnoCqQaSk32LPGRTPJrYbL3rie6KrTgXmkiWqRRqMYrkp8MiVRSbsN1Hy76km1lt/uh3srXkhM7YLdUp3efVOr2GO2301asEAJK/WAGZHIb5V8R6Qj7LB54v/n62coexOJKq77q6fLB5cgaHdt3nBJWC6Z4aLf66CsvwP6tUsgO7XcD9n root@ubuntu 
#########################################################
Root Directory Discovering ..
#########################################################
Home Directory Discovering ..
Check Home_Dir.txt
#########################################################
Discovering Var Directory ...
Check Var_Directory.txt
#########################################################
Discovering Logs  ...
Check Logs_var.txt
#################### Network Info #######################
#########################################################
#########################################################
Internal IP : 
192.168.56.103
#########################################################
ARP IPs :
192.168.56.1
192.168.56.100
#########################################################
TCP Connections : 
tcp        0      0 0.0.0.0:993             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN     
tcp        0      0 192.168.56.103:22       192.168.56.1:58457      ESTABLISHED
tcp6       0      0 :::993                  :::*                    LISTEN     
tcp6       0      0 :::143                  :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
#########################################################
#################### Users Info #########################
#########################################################
#########################################################
 Users List 
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
libuuid
syslog
messagebus
whoopsie
landscape
sshd
ft_root
mysql
ftp
lmezard
laurie@borntosec.net
laurie
thor
zaz
dovecot
dovenull
postfix
#########################################################
 UID List 
0
1
2
3
4
5
6
7
8
9
10
13
33
34
38
39
41
65534
100
101
102
103
104
105
1000
106
107
1001
1002
1003
1004
1005
108
109
110
#########################################################
 GID List 
0
1
2
3
65534
60
12
7
8
9
10
13
33
34
38
39
41
65534
101
103
106
107
110
65534
1000
115
116
1001
1002
1003
1004
1005
117
65534
118
#########################################################
 Root List 
root
#########################################################
crontab: option requires an argument -- 'u'
crontab: usage error: unrecognized option
usage:  crontab [-u user] file
        crontab [ -u user ] [ -i ] { -e | -l | -r }
                (default operation is replace, per 1003.2)
        -e      (edit user's crontab)
        -l      (list user's crontab)
        -r      (delete user's crontab)
        -i      (prompt before deleting user's crontab)
 Cron Jobs List 
-rw-r--r-- 1 root root 722 Apr  2  2012 /etc/crontab

/etc/cron.d:
total 2
drwxr-xr-x 2 root root  47 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Aug 21 11:48 ..
-rw-r--r-- 1 root root 544 Sep 30  2015 php5
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder

/etc/cron.daily:
total 29
drwxr-xr-x 2 root root   275 Oct  8  2015 .
drwxr-xr-x 1 root root   420 Aug 21 11:48 ..
-rwxr-xr-x 1 root root   633 Jul 24  2015 apache2
-rwxr-xr-x 1 root root   219 Apr 10  2012 apport
-rwxr-xr-x 1 root root 15399 Apr 20  2012 apt
-rwxr-xr-x 1 root root   314 Apr 19  2013 aptitude
-rwxr-xr-x 1 root root   502 Mar 31  2012 bsdmainutils
-rwxr-xr-x 1 root root   256 Apr 13  2012 dpkg
-rwxr-xr-x 1 root root   372 Oct  4  2011 logrotate
-rwxr-xr-x 1 root root  1365 Sep 23  2014 man-db
-rwxr-xr-x 1 root root   606 Aug 17  2011 mlocate
-rwxr-xr-x 1 root root   249 Apr  9  2012 passwd
-rw-r--r-- 1 root root   102 Apr  2  2012 .placeholder
-rwxr-xr-x 1 root root  2417 Jul  1  2011 popularity-contest
-rwxr-xr-x 1 root root   330 Jul 27  2011 squirrelmail
-rwxr-xr-x 1 root root  2947 Apr  2  2012 standard
-rwxr-xr-x 1 root root   214 Jul  1  2014 update-notifier-common

/etc/cron.hourly:
total 1
drwxr-xr-x 2 root root  35 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Aug 21 11:48 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder

/etc/cron.monthly:
total 1
drwxr-xr-x 2 root root  35 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Aug 21 11:48 ..
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder

/etc/cron.weekly:
total 3
drwxr-xr-x 2 root root  73 Oct  8  2015 .
drwxr-xr-x 1 root root 420 Aug 21 11:48 ..
-rwxr-xr-x 1 root root 730 Sep 13  2013 apt-xapian-index
-rwxr-xr-x 1 root root 907 Sep 23  2014 man-db
-rw-r--r-- 1 root root 102 Apr  2  2012 .placeholder
#########################################################
 Own Crontab List 
whoami
#########################################################
 Cron Jobs Content 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```
