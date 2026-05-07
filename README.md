# CVE-2026-31431 — "Copy Fail" Safe Detection Script

> A read-only detection script for the **Copy Fail** Linux kernel local privilege escalation vulnerability.  
> No exploit code. No AF\_ALG socket opened. No files written outside `/etc/modprobe.d` (only when you apply the mitigation manually).

---

## Background

**Copy Fail** (CVE-2026-31431) is a logic flaw in the Linux kernel's `algif_aead` module — part of the AF\_ALG userspace crypto API. It was disclosed on **April 29, 2026** by [Theori / Xint Code](https://xint.io/blog/copy-fail-linux-distributions).

A 732-byte Python script can give an unprivileged local user full root access on virtually every major Linux distribution built since 2017 — without race conditions, kernel offsets, or compiled payloads.

| Property | Detail |
|---|---|
| CVE | CVE-2026-31431 |
| CVSS | 7.8 HIGH |
| Type | Local Privilege Escalation (LPE) |
| Affected kernels | 4.14 – 6.18.21, 6.19.0 – 6.19.11 |
| Root cause | `algif_aead` in-place optimization (commit `72548b093ee3`, 2017) |
| Upstream fix | Revert via commit `a664bf3d603d` |
| Exploit reliability | Deterministic — no race condition required |

---

## What the script checks

1. **Kernel version** — whether the running kernel falls within the vulnerable upstream range
2. **algif\_aead module state** — loaded, built-in, or absent
3. **Active mitigations** — `modprobe.d` blacklist, `initcall_blacklist` kernel cmdline param
4. **Distro-specific patch status** — for Debian/Ubuntu/Parrot: verifies the `kmod` package version per USN-8226-1

> **Note on Ubuntu / Debian:** Ubuntu does not bump the upstream kernel version when backporting security patches. The script therefore checks the `kmod` package version (`>= 31+20240202-2ubuntu7.2` per USN-8226-1) rather than relying on the kernel version string alone.

---

## Supported distributions

| Distribution | Check method |
|---|---|
| Ubuntu / Linux Mint | `kmod` package version (USN-8226-1) |
| Debian | `kmod` package version + security tracker |
| Parrot OS | `kmod` package version (Debian rolling) |
| RHEL / CentOS / AlmaLinux / Rocky | `dnf updateinfo` + `initcall_blacklist` cmdline |
| Fedora | `dnf updateinfo` |
| Amazon Linux | `dnf check-update --security` |
| SUSE / openSUSE | `zypper lp` |
| Arch Linux | `pacman -Syu linux` |

---

## Usage

```bash
# Download
curl -O https://raw.githubusercontent.com/kw-soft/copyfail/main/copyfail.sh

# Make executable
chmod +x copyfail.sh

# Run (root recommended for full module visibility)
sudo ./copyfail.sh
```

---

## Example output

### Vulnerable system
```
============================================
  CVE-2026-31431 'Copy Fail' — Safe Detection
============================================
[*] Kernel: 6.8.0-71-generic
[!] Kernel 6.8.0-71-generic is in the vulnerable upstream range (4.14 – 6.19.11)
[~] Distro backport check follows — version number alone is not conclusive
[*] algif_aead module status:
[!] algif_aead is LOADED — attack surface is active
[*] Distribution patch status:
    Distro : Ubuntu 24.04
    kmod installed : 31+20240202-2ubuntu6
    kmod required  : >= 31+20240202-2ubuntu7.2
[!] kmod 31+20240202-2ubuntu6 < 31+20240202-2ubuntu7.2 — mitigation NOT applied
============================================
  RESULT
============================================
[!] VULNERABLE — kernel affected and algif_aead is active
```

### Mitigated system
```
============================================
  CVE-2026-31431 'Copy Fail' — Safe Detection
============================================
[*] Kernel: 6.8.0-71-generic
[!] Kernel 6.8.0-71-generic is in the vulnerable upstream range (4.14 – 6.19.11)
[~] Distro backport check follows — version number alone is not conclusive
[*] algif_aead module status:
[✓] algif_aead is NOT loaded
[✓] modprobe blacklist active: /etc/modprobe.d/disable-algif_aead.conf
[*] Distribution patch status:
    Distro : Ubuntu 24.04
    kmod installed : 31+20240202-2ubuntu7.2
    kmod required  : >= 31+20240202-2ubuntu7.2
[✓] kmod >= 31+20240202-2ubuntu7.2 — USN-8226-1 mitigation present
============================================
  RESULT
============================================
[✓] MITIGATED — algif_aead is blocked
[~] Apply a patched kernel when available to fully resolve the issue
```

---

## Applying the mitigation

### Debian / Ubuntu / Parrot / Linux Mint
```bash
sudo apt update && sudo apt upgrade && sudo reboot
```
This installs the patched `kmod` package (USN-8226-1) which drops a `modprobe.d` rule blocking `algif_aead`.

If an immediate reboot is not possible:
```bash
echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf
sudo update-initramfs -u
sudo rmmod algif_aead 2>/dev/null || echo "Module in use — reboot required"
```

### RHEL / CentOS / AlmaLinux / Rocky
> ⚠️ On RHEL-family kernels, `algif_aead` is **built into the kernel** (`CONFIG_CRYPTO_USER_API_AEAD=y`).  
> `modprobe.d` rules have **no effect**. Use the grub parameter instead:

```bash
sudo grubby --update-kernel=ALL --args='initcall_blacklist=algif_aead_init'
sudo reboot
```

### Arch Linux
```bash
sudo pacman -Syu linux && sudo reboot
```

---

## What is NOT affected

The mitigation does not impact any of the following:

- `dm-crypt` / LUKS full-disk encryption
- SSH
- IPsec / XFRM
- OpenSSL (default build)
- GnuTLS / NSS
- kTLS

Only applications explicitly configured to use the `afalg` engine or that bind AF\_ALG AEAD sockets directly may be affected — this is rare in standard deployments.

---

## Checking automatic updates (Ubuntu)

Hetzner does **not** apply OS updates automatically. Ubuntu ships `unattended-upgrades` pre-installed, but it must be enabled and configured.

```bash
# Check if automatic security updates are active
cat /etc/apt/apt.conf.d/20auto-upgrades

# View upgrade history
grep "^Start-Date\|^Commandline" /var/log/apt/history.log | tail -30

# Check if the kmod mitigation was applied automatically
grep "kmod\|algif" /var/log/apt/history.log

# Check last unattended-upgrades run
tail -30 /var/log/unattended-upgrades/unattended-upgrades.log
```

> **Note:** Even with `unattended-upgrades` enabled, automatic reboots are **off by default**.  
> A new kernel only becomes active after a manual `reboot`.

---

## References

| Resource | Link |
|---|---|
| Original writeup | https://xint.io/blog/copy-fail-linux-distributions |
| NVD | https://nvd.nist.gov/vuln/detail/CVE-2026-31431 |
| Ubuntu advisory | https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available |
| USN-8226-1 | https://ubuntu.com/security/notices/USN-8226-1 |
| CERT-EU advisory | https://cert.europa.eu/publications/security-advisories/2026-005/ |
| Debian tracker | https://security-tracker.debian.org/tracker/CVE-2026-31431 |
| Microsoft blog | https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/ |
| Wikipedia | https://en.wikipedia.org/wiki/Copy_Fail |

---

## Disclaimer

This script is intended for use on systems you own or are authorized to test.  
It performs read-only checks and does not exploit the vulnerability in any way.
