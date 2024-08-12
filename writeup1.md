![image](https://github.com/user-attachments/assets/c9612de8-e6e5-44b9-b864-54eeb0410f6e)`$ ifconfig`

![image](https://github.com/user-attachments/assets/ca4fd3bb-b9af-426c-8050-4502cfd94372)

nmap - Network exploration tool and security / port scanner

`$ nmap -sP 192.168.56.0/24`

![image](https://github.com/user-attachments/assets/88d8f879-1eae-4108-9d7a-98da258df4c7)

`$ ping 192.168.56.103`

![image](https://github.com/user-attachments/assets/246a5ac7-bcf6-4abe-aa4e-a8a1ae994a14)

`$ nmap -sV 192.168.56.103`

![image](https://github.com/user-attachments/assets/9192dcd2-6b76-41f9-b98e-e91de935619f)

![image](https://github.com/user-attachments/assets/432e65e0-151f-4ee0-a6dc-0deee264f9d2)

![image](https://github.com/user-attachments/assets/11e9b058-a8a1-445a-81de-36cde81760e4)

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

# Directory Enumeration

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
I assumed the server would be running on http but nothing substantial came out of this search so I was mistaken.

`dirb https://192.168.56.103/ -o dirb.txt`

![image](https://github.com/user-attachments/assets/3931c147-cee5-499a-9fb9-b2c15577fcc5)

Too many results, it will be hard to effectively go through it all but I will save them in a seperate file just in case. 

`$ dirb https://192.168.56.103/ -r`         

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Aug 12 04:35:41 2024
URL_BASE: https://192.168.56.103/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

                                                                            GENERATED WORDS: 4612

---- Scanning URL: https://192.168.56.103/ ----
                                                                            + https://192.168.56.103/cgi-bin/ (CODE:403|SIZE:291)                      
                                                                            ==> DIRECTORY: https://192.168.56.103/forum/
                                                                            ==> DIRECTORY: https://192.168.56.103/phpmyadmin/
+ https://192.168.56.103/server-status (CODE:403|SIZE:296)                 
                                                                            ==> DIRECTORY: https://192.168.56.103/webmail/
                                                                               
-----------------
END_TIME: Mon Aug 12 04:35:45 2024
DOWNLOADED: 4612 - FOUND: 2
```

With the **non-recursive** option dirb will just list the first level directories of the main URL that was specified in the command. We don't have the permission to access 2 of these directories as indicated by the **403 status code**. But we 3 new directories ready for inspection:
- /forum
- /phpmyadmin
- /webmail

## /forum

![image](https://github.com/user-attachments/assets/a3fb315d-23a3-4d81-8110-b9c7e3221582)

![image](https://github.com/user-attachments/assets/daf8c625-7a02-4013-ba44-c58a47ab1196)

`Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2`


`Username: lmezard`

`Password: !q\]Ej?*5K5cy*AJ`

![image](https://github.com/user-attachments/assets/e2fa56be-582c-49f6-b0f2-442d6b336b5e)

![image](https://github.com/user-attachments/assets/6e796a36-c732-4ed0-89c6-1efe063a89b9)

`laurie@borntosec.net`

## /webmail

![image](https://github.com/user-attachments/assets/8ea8e0e3-ab2c-48fa-9b5e-1b8615bc9232)

We can login with the previous credentials.

![image](https://github.com/user-attachments/assets/7889eec2-fc09-4af0-ac34-f88e129f5de3)

```
Subject:   	DB Access
From:   	qudevide@mail.borntosec.net
Date:   	Thu, October 8, 2015 11:25 pm
To:   	laurie@borntosec.net
Priority:   	Normal
Options:   	View Full Header |  View Printable Version  | Download this as a file

Hey Laurie,

You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$

Best regards.
```
## /phpmyadmin

![image](https://github.com/user-attachments/assets/be7db68a-8a54-4f1d-aaaa-9d180283e56c)

![image](https://github.com/user-attachments/assets/a2ad9a22-869f-4af9-9d0d-fd54e089b8b8)

![image](https://github.com/user-attachments/assets/a0a54a24-f5fe-48bd-bda8-05af5acf86dc)

![image](https://github.com/user-attachments/assets/2e3ded56-1946-4311-8a51-3397aea3e58f)

`ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0516d551c28`

So, we were able to get the password hash for the admin. But I was unable to crack the hash. The old friend `john` or `crackstation` couldn't help. It would have been good to know more about the kind of hashing alghoritm they used. Let's see if we can figure that out.

We see that the forum is powered by [mylittleforum](https://mylittleforum.net/) which is a simple PHP and MySQL based internet forum that displays the messages in classical threaded view (tree structure). It is Open Source licensed under the GNU General Public License.

![image](https://github.com/user-attachments/assets/f25df078-8aa2-4ca9-8516-6f57e0b809f9)

We can navigate to the source code from here:

![image](https://github.com/user-attachments/assets/a277dca3-a31b-49dc-b5dc-3b260716da97)

![image](https://github.com/user-attachments/assets/28fe96ca-0d14-4bac-a89a-283e0f8cf22b)
