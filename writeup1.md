`$ ifconfig`

![image](https://github.com/user-attachments/assets/ca4fd3bb-b9af-426c-8050-4502cfd94372)

nmap - Network exploration tool and security / port scanner

`$ nmap -sP 192.168.56.0/24`

![image](https://github.com/user-attachments/assets/88d8f879-1eae-4108-9d7a-98da258df4c7)

`$ ping 192.168.56.103`

![image](https://github.com/user-attachments/assets/246a5ac7-bcf6-4abe-aa4e-a8a1ae994a14)

`$ nmap -sV 192.168.56.103`

![image](https://github.com/user-attachments/assets/9192dcd2-6b76-41f9-b98e-e91de935619f)

![image](https://github.com/user-attachments/assets/432e65e0-151f-4ee0-a6dc-0deee264f9d2)

`$ nikto -h http://192.168.56.103`

```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.103
+ Target Hostname:    192.168.56.103
+ Target Port:        80
+ Start Time:         2024-08-09 13:46:42 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ /: Server may leak inodes via ETags, header found with file /, inode: 13650, size: 1025, mtime: Wed Oct  7 19:37:54 2015. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: OPTIONS, GET, HEAD, POST .
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8909 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-08-09 13:47:02 (GMT-4) (20 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`$ dirb http://192.168.56.103`
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Aug  9 13:50:48 2024
URL_BASE: http://192.168.56.103/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

                                                                           GENERATED WORDS: 4612

---- Scanning URL: http://192.168.56.103/ ----
                                                                           + http://192.168.56.103/cgi-bin/ (CODE:403|SIZE:290)                      
                                                                           ==> DIRECTORY: http://192.168.56.103/fonts/
+ http://192.168.56.103/forum (CODE:403|SIZE:287)                         
+ http://192.168.56.103/index.html (CODE:200|SIZE:1025)                   
+ http://192.168.56.103/server-status (CODE:403|SIZE:295)                 
                                                                          
---- Entering directory: http://192.168.56.103/fonts/ ----
                                                                           (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Aug  9 13:50:52 2024
DOWNLOADED: 4612 - FOUND: 4
```
