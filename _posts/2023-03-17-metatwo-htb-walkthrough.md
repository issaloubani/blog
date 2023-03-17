---
published: false
---
## HackTheBox Metatwo Walkthrough

![Metatwo Info]({{site.baseurl}}/images/metatwo_info.jpg)


Starting with nmap, we can see that the machine has 3 ports open :


```
┌──(kali㉿kali)-[~]
└─$ nmap metapress.htb    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 11:36 EDT
Nmap scan report for metapress.htb (10.10.11.186)
Host is up (0.077s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.81 seconds

```
Visiting the http server on port 80, and after some digging, we can clearly see that it is a wordpress server, which might contain an admin panel that we can use to controll the site and that might contain a vuln that we can use to exploit the server.

![Metatwo Panel]({{site.baseurl}}/_posts/metatwo/panel.jpg)

Using the default credentials did not work. We can further explore the server using wpscan tool in kali:
IMAGE_NEEDED_HERE

The wpscan showed us a lot of useful information, including the version of the used wordpress along with some CVEs that we can use.

After some digging I found some exploit that we can use to read files from the server, but we need to be authenticated first. We can try to crack the credentials of the panel using wpscan along with the rockyou wordlist.

AFter some time, I was able to get the credential of the panel.

# ****CVE-2022-0739****

The vuln is a little bit complicated, but it is as follows, with some prerequisites.

- We need an http server that the mp4 will try to read some commands for it (to know which file to read and send it back)
- We need a special file that is used to specify the target file we need to read.

We first create the mp3 audio file using the following command, and replacing the needed variables with our own:
INSERT IMAGE HERE

After that we need to create another file with a dpd extension, specifying with file to read and the server which will send the content of the target file to it.

I named the file drop.dpd, the name of the file does not effect the exploit.

After creating all files, we start our server using the following command:

INSERT_COMMAND

#### CVE In action


