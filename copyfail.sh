#!/usr/bin/env bash
# CVE-2026-31431 "Copy Fail" — safe detection script
# Affected: Linux kernel 4.14 – 6.18.21 / 6.19.0 – 6.19.11 (algif_aead LPE)
# Ubuntu fix: kmod >= 31+20240202-2ubuntu7.2 (USN-8226-1) disables algif_aead
# Safe: read-only checks only, no AF_ALG socket opened, no exploit code

set -euo pipefail
IFS=$'\n\t'

# ── colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    R='\033[0;31m' Y='\033[1;33m' G='\033[0;32m' B='\033[0;34m' N='\033[0m'
else
    R='' Y='' G='' B='' N=''
fi

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "${B}[*]${N} $*"; }
ok()    { echo -e "${G}[✓]${N} $*"; }
warn()  { echo -e "${Y}[~]${N} $*"; }
alert() { echo -e "${R}[!]${N} $*"; }

dpkg_ge() { dpkg --compare-versions "$1" ge "$2" 2>/dev/null; }

# ── globals ───────────────────────────────────────────────────────────────────
KERNEL_VULN=1
MODULE_LOADED=0
MODULE_MITIGATED=0
DISTRO_PATCHED=0

# ── kernel version ────────────────────────────────────────────────────────────
check_kernel() {
    local krel; krel=$(uname -r)
    local kmaj kmin kpat
    kmaj=$(echo "$krel" | cut -d. -f1)
    kmin=$(echo "$krel" | cut -d. -f2)
    kpat=$(echo "$krel" | cut -d. -f3 | grep -oP '^\d+' || echo 0)

    info "Kernel: ${B}${krel}${N}"

    # below 4.14 — regression not yet introduced
    if [[ $kmaj -lt 4 ]] || [[ $kmaj -eq 4 && $kmin -lt 14 ]]; then
        ok "Kernel predates vulnerable range (< 4.14)"; KERNEL_VULN=0; return
    fi

    # upstream-patched thresholds
    if   [[ $kmaj -ge 7 ]]; then
        ok "Kernel >= 7.x — upstream patched"; KERNEL_VULN=0; return
    elif [[ $kmaj -eq 6 && $kmin -eq 18 && $kpat -ge 22 ]]; then
        ok "Kernel 6.18.${kpat} >= 6.18.22 — upstream patched"; KERNEL_VULN=0; return
    elif [[ $kmaj -eq 6 && $kmin -eq 19 && $kpat -ge 12 ]]; then
        ok "Kernel 6.19.${kpat} >= 6.19.12 — upstream patched"; KERNEL_VULN=0; return
    elif [[ $kmaj -eq 6 && $kmin -ge 20 ]]; then
        ok "Kernel 6.${kmin}.x — upstream patched"; KERNEL_VULN=0; return
    fi

    # Distros (esp. Debian/Ubuntu) backport fixes without bumping upstream version.
    # Kernel version alone is NOT conclusive — check_distro() does the final call.
    alert "Kernel ${krel} is in the vulnerable upstream range (4.14 – 6.19.11)"
    warn  "Distro backport check follows — version number alone is not conclusive"
}

# ── algif_aead module ─────────────────────────────────────────────────────────
check_module() {
    info "algif_aead module status:"

    if lsmod 2>/dev/null | grep -q '^algif_aead'; then
        alert "algif_aead is LOADED — attack surface is active"
        MODULE_LOADED=1
    elif grep -q 'algif_aead' /proc/modules 2>/dev/null; then
        alert "algif_aead present in /proc/modules (built-in)"
        MODULE_LOADED=1
    else
        ok "algif_aead is NOT loaded"
    fi

    # modprobe blacklist (Debian/Ubuntu/Parrot)
    if grep -rqs 'algif_aead' /etc/modprobe.d/ 2>/dev/null; then
        local f; f=$(grep -rl 'algif_aead' /etc/modprobe.d/ | head -1)
        if grep -qs 'install.*false\|blacklist' "$f" 2>/dev/null; then
            ok "modprobe blacklist active: ${f}"
            MODULE_MITIGATED=1
        fi
    fi

    # RHEL-family: initcall_blacklist via grubby
    if grep -qs 'initcall_blacklist=algif_aead_init' /proc/cmdline 2>/dev/null; then
        ok "initcall_blacklist=algif_aead_init set on kernel cmdline"
        MODULE_MITIGATED=1
    fi
}

# ── Ubuntu/Debian: kmod package check (USN-8226-1) ───────────────────────────
check_deb_kmod() {
    # Ubuntu ships the mitigation via kmod, not a new kernel package.
    # Fixed version per USN-8226-1: 31+20240202-2ubuntu7.2
    local fixed_kmod="31+20240202-2ubuntu7.2"
    local installed_kmod
    installed_kmod=$(dpkg-query -W -f='${Version}' kmod 2>/dev/null || echo "")

    if [[ -z "$installed_kmod" ]]; then
        warn "kmod package not found via dpkg"; return
    fi

    echo "    kmod installed : ${installed_kmod}"
    echo "    kmod required  : >= ${fixed_kmod}"

    if dpkg_ge "$installed_kmod" "$fixed_kmod"; then
        ok "kmod >= ${fixed_kmod} — USN-8226-1 mitigation present"
        DISTRO_PATCHED=1
        MODULE_MITIGATED=1
    else
        alert "kmod ${installed_kmod} < ${fixed_kmod} — mitigation NOT applied"
        warn  "Run: sudo apt update && sudo apt upgrade && sudo reboot"
    fi
}

# ── distro-specific checks ────────────────────────────────────────────────────
check_distro() {
    info "Distribution patch status:"
    [[ -f /etc/os-release ]] || { warn "Cannot read /etc/os-release"; return; }

    local id version_id name
    # shellcheck source=/dev/null
    source /etc/os-release
    id="${ID:-unknown}"
    version_id="${VERSION_ID:-unknown}"
    name="${NAME:-${id}}"

    echo "    Distro : ${name} ${version_id}"

    case "$id" in
        ubuntu|linuxmint)
            if dpkg_ge "${version_id}" "26.04" 2>/dev/null; then
                ok "Ubuntu 26.04+ ships an unaffected kernel"; KERNEL_VULN=0; return
            fi
            check_deb_kmod
            ;;
        parrot)
            # Parrot is Debian-based rolling — kmod check applies
            warn "Parrot OS (Debian rolling): checking kmod mitigation..."
            check_deb_kmod
            warn "Track: https://security-tracker.debian.org/tracker/CVE-2026-31431"
            ;;
        debian)
            check_deb_kmod
            warn "Track: https://security-tracker.debian.org/tracker/CVE-2026-31431"
            ;;
        rhel|centos|almalinux|rocky)
            warn "Run:  dnf updateinfo list security | grep CVE-2026-31431"
            warn "NOTE: algif_aead is built-in on RHEL-family — modprobe.d has NO effect"
            warn "      Use: grubby --update-kernel=ALL --args=initcall_blacklist=algif_aead_init"
            ;;
        fedora)
            warn "Run: dnf updateinfo list security | grep CVE-2026-31431"
            ;;
        amzn)
            warn "Run: dnf check-update --security | grep kernel"
            ;;
        sles|opensuse*|suse*)
            warn "Run: zypper lp | grep CVE-2026-31431"
            ;;
        arch)
            warn "Run: sudo pacman -Syu linux"
            ;;
        *)
            warn "Unknown distro '${id}' — check vendor security tracker manually"
            ;;
    esac
}

# ── mitigation hint ───────────────────────────────────────────────────────────
print_mitigation() {
    echo
    echo -e "${Y}  Interim mitigation (until kernel is patched):${N}"
    echo
    echo "  # Debian / Ubuntu / Parrot / Mint:"
    echo "  sudo apt update && sudo apt upgrade && sudo reboot"
    echo "  # If reboot is not immediately possible:"
    echo "  echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf"
    echo "  sudo update-initramfs -u"
    echo "  sudo rmmod algif_aead 2>/dev/null || echo 'Module in use — reboot required'"
    echo
    echo "  # RHEL / CentOS / AlmaLinux / Rocky (built-in — grub param required):"
    echo "  sudo grubby --update-kernel=ALL --args='initcall_blacklist=algif_aead_init'"
    echo "  sudo reboot"
    echo
    echo -e "${Y}  Not affected: SSH, dm-crypt/LUKS, IPsec, OpenSSL, GnuTLS, kTLS${N}"
}

# ── summary ───────────────────────────────────────────────────────────────────
print_summary() {
    echo
    echo -e "${B}$(printf '=%.0s' {1..44})${N}"
    echo -e "${B}  RESULT${N}"
    echo -e "${B}$(printf '=%.0s' {1..44})${N}"

    if [[ $KERNEL_VULN -eq 0 ]]; then
        ok "NOT VULNERABLE — kernel is outside the affected range"
    elif [[ $DISTRO_PATCHED -eq 1 ]] || [[ $MODULE_MITIGATED -eq 1 && $MODULE_LOADED -eq 0 ]]; then
        ok "MITIGATED — algif_aead is blocked"
        warn "Apply a patched kernel when available to fully resolve the issue"
    elif [[ $MODULE_LOADED -eq 1 && $MODULE_MITIGATED -eq 0 ]]; then
        alert "VULNERABLE — kernel affected and algif_aead is active"
        print_mitigation
    else
        warn "UNCERTAIN — kernel in affected range, module not currently loaded"
        warn "Without a blacklist the module may load on demand or after reboot."
        print_mitigation
    fi

    echo
    echo "  References:"
    echo "    Ubuntu advisory  https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available"
    echo "    USN-8226-1       https://ubuntu.com/security/notices/USN-8226-1"
    echo "    NVD              https://nvd.nist.gov/vuln/detail/CVE-2026-31431"
    echo "    Original WU      https://xint.io/blog/copy-fail-linux-distributions"
    echo "    CERT-EU          https://cert.europa.eu/publications/security-advisories/2026-005/"
    echo -e "${B}$(printf '=%.0s' {1..44})${N}"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    [[ $(id -u) -ne 0 ]] && warn "Running without root — some checks may be incomplete"

    echo
    echo -e "${B}$(printf '=%.0s' {1..44})${N}"
    echo -e "${B}  CVE-2026-31431 'Copy Fail' — Safe Detection${N}"
    echo -e "${B}$(printf '=%.0s' {1..44})${N}"
    echo

    check_kernel
    echo
    check_module
    echo
    check_distro
    print_summary
}

main "$@"