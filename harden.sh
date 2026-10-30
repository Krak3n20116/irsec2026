#!/usr/bin/env bash
# harden.sh - "first five minutes" hardening for Ubuntu Desktop + Server
# Logic for 20.04 / 22.04 / 24.04. Run as root:  sudo ./harden.sh
#
# Before every step the script says, in plain text, what it is about to do
# and waits for an answer:
#     y = do it    n = skip it    a = do this and all remaining steps    q = quit
#
#   DRY_RUN=1 sudo ./harden.sh     -> show what would change, change nothing
#   CONFIRM=0 sudo ./harden.sh     -> no prompts, run every step
#
# The firewall step will cut off any service whose port is not allowed.

set -uo pipefail

########################## CONFIG ##########################
ALLOWED_PORTS="${ALLOWED_PORTS:-22/tcp}"      # e.g. "22/tcp 80/tcp 443/tcp 53"
AUTHORIZED_USERS="${AUTHORIZED_USERS:-}"      # e.g. "alice bob" (blank = report only)
LOCK_UNAUTHORIZED="${LOCK_UNAUTHORIZED:-0}"   # 1 = lock login users not in list above
DRY_RUN="${DRY_RUN:-0}"
CONFIRM="${CONFIRM:-1}"                       # 0 = don't ask before each step
FTP_ANON="${FTP_ANON:-0}"                     # 1 = keep anonymous FTP (only if scoring needs it)
PASV_MIN="${PASV_MIN:-40000}"                 # FTP passive port range
PASV_MAX="${PASV_MAX:-40100}"
############################################################
# Ports for detected roles are added automatically:
#   Wazuh manager -> 443 1514 1515 55000/tcp
#   vsftpd        -> 21/tcp + passive range
#   Docker        -> published container ports BYPASS ufw (see Docker step)

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
OUT="/root/harden-$TS"
mkdir -p "$OUT"
LOG="$OUT/harden.log"
exec > >(tee -a "$LOG") 2>&1

c()   { echo -e "\n\e[1;36m== $* ==\e[0m"; }
warn(){ echo -e "\e[1;33m[!] $*\e[0m"; }
run() { if [[ $DRY_RUN == 1 ]]; then echo "[dry-run] $*"; else eval "$*"; fi; }

# step "Title" "plain-text explanation"  -> returns 0 to run the step, 1 to skip
STEP_NO=0
step() {
  STEP_NO=$((STEP_NO+1))
  echo
  echo "------------------------------------------------------------"
  echo "STEP $STEP_NO: $1"
  echo "------------------------------------------------------------"
  echo "$2"
  echo
  if [[ $CONFIRM != 1 ]]; then c "$1"; return 0; fi
  local ans
  while true; do
    printf "Do this step? [y]es / [n]o (skip) / [a]ll remaining / [q]uit: "
    read -r ans </dev/tty
    case "${ans,,}" in
      y|yes) c "$1"; return 0 ;;
      n|no)  echo "Skipped: $1"; echo "SKIPPED step $STEP_NO: $1" >> "$OUT/skipped.txt"; return 1 ;;
      a|all) CONFIRM=0; c "$1"; return 0 ;;
      q|quit) echo "Stopped by user before step $STEP_NO. Log: $LOG"; exit 0 ;;
      *) echo "Please type y, n, a or q." ;;
    esac
  done
}

# ---------- Detect (read-only, always runs) ----------
. /etc/os-release
VER="$VERSION_ID"
if dpkg -l 2>/dev/null | grep -qE '^ii\s+(ubuntu-desktop|gdm3|lightdm)\b'; then
  FLAVOR=desktop; else FLAVOR=server; fi
HAS_DOCKER=0; systemctl is-active --quiet docker 2>/dev/null && HAS_DOCKER=1
HAS_VSFTPD=0; [[ -f /etc/vsftpd.conf ]] && HAS_VSFTPD=1
HAS_WAZUH=0;  systemctl cat wazuh-manager &>/dev/null && HAS_WAZUH=1
for f in proftpd pure-ftpd; do systemctl cat "$f" &>/dev/null && warn "$f found - script only auto-hardens vsftpd"; done

[[ $HAS_WAZUH  == 1 ]] && ALLOWED_PORTS+=" 443/tcp 1514/tcp 1515/tcp 55000/tcp"
[[ $HAS_VSFTPD == 1 ]] && ALLOWED_PORTS+=" 21/tcp $PASV_MIN:$PASV_MAX/tcp"
ALLOWED_PORTS=$(tr ' ' '\n' <<<"$ALLOWED_PORTS" | awk 'NF && !s[$0]++' | xargs)

UID0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | xargs)
EMPTY=$(awk -F: '$2==""{print $1}' /etc/shadow | xargs)

c "Ubuntu $VER ($FLAVOR)  docker=$HAS_DOCKER vsftpd=$HAS_VSFTPD wazuh=$HAS_WAZUH  dry_run=$DRY_RUN"
echo "Log for this run: $LOG"
[[ $DRY_RUN == 1 ]] && echo "DRY RUN: nothing will actually be changed."

# ---------- 1. Backup ----------
if step "Back up /etc" \
"Copies the whole /etc folder into $OUT/etc-backup.tgz and a second
copy into /var/lib. Nothing on the system is changed. This is your
rollback point if a later step breaks something."; then
  tar czf "$OUT/etc-backup.tgz" /etc 2>/dev/null && echo "saved $OUT/etc-backup.tgz"
  cp "$OUT/etc-backup.tgz" "/var/lib/.etcbk-$TS.tgz" 2>/dev/null
fi

# ---------- 2. Baseline snapshot ----------
if step "Record a baseline snapshot" \
"Writes a report to $OUT/baseline.txt listing: users who can log in,
admin/sudo members, open ports, enabled services, cron jobs, timers,
SSH keys and other places attackers hide. Read-only, changes nothing."; then
  {
    echo "### Login-capable users";  awk -F: '$7!~/(nologin|false)$/{print $1,$3,$7}' /etc/passwd
    echo "### UID 0 accounts";       awk -F: '$3==0{print $1}' /etc/passwd
    echo "### Empty passwords";      awk -F: '$2==""{print $1}' /etc/shadow
    echo "### sudo/admin members";   getent group sudo admin
    echo "### sudoers NOPASSWD";     grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d 2>/dev/null
    echo "### Listening sockets";    ss -tulpn
    echo "### Enabled services";     systemctl list-unit-files --state=enabled --no-pager
    echo "### Cron";                 ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null; cat /etc/crontab
    echo "### systemd timers";       systemctl list-timers --all --no-pager
    echo "### authorized_keys";      find / -xdev -name authorized_keys -exec ls -l {} \; -exec cat {} \; 2>/dev/null
    echo "### rc.local / profile.d"; ls -la /etc/rc.local /etc/profile.d 2>/dev/null
    echo "### ld.so.preload";        cat /etc/ld.so.preload 2>/dev/null
  } > "$OUT/baseline.txt"
  echo "saved $OUT/baseline.txt"
  [[ -n $UID0 ]]  && warn "Non-root UID 0 accounts: $UID0"
  [[ -n $EMPTY ]] && warn "Accounts with EMPTY passwords: $EMPTY"
  [[ -s /etc/ld.so.preload ]] && warn "/etc/ld.so.preload is not empty - check for rootkit"
fi

# ---------- 2b. Persistence hunt ----------
# Patterns that usually mean a reverse shell, downloader or backdoor
SUS='(/dev/(tcp|udp)/|\bnc(at)?\b.*\s-[a-z]*[ec]|bash -i|sh -i|mkfifo|socat|python[0-9.]* -c|perl -e|ruby -e|php -r|base64 (-d|--decode)|(curl|wget)[^|;]*\|\s*(ba)?sh|/tmp/|/dev/shm/|/var/tmp/|chmod ([ugoa]*[+]s|[0-7]?[2467][0-7]{3})|chattr|useradd|usermod|nohup|LD_PRELOAD)'
PERSIST_DAYS="${PERSIST_DAYS:-7}"
if step "Hunt for persistence (backdoors)" \
"Read-only. Checks every common place an attacker hides something that
re-runs or lets them back in:
  - cron (system + every user), anacron, at jobs, systemd timers
  - custom systemd services (system and per-user)
  - shell startup files (.bashrc, .profile, /etc/profile.d ...)
  - rc.local, init.d, login messages (update-motd.d), APT hooks,
    udev rules, desktop autostart, PAM, ld.so.preload
  - SSH keys and ~/.ssh/rc
  - processes running from /tmp, /dev/shm or deleted files
  - files changed in the last $PERSIST_DAYS days and system binaries that
    don't match their package (takes up to 2 minutes)
Anything matching a reverse-shell/downloader pattern is shown in yellow.
Full report: $OUT/persistence.txt. Nothing is deleted or disabled."; then
  P="$OUT/persistence.txt"; : > "$P"
  HOMES=$(awk -F: '($3==0 || $3>=1000) && $3<65534 {print $6}' /etc/passwd | sort -u)

  owned() { local r; r=$(readlink -f "$1")
            dpkg -S "$1" &>/dev/null || dpkg -S "$r" &>/dev/null || dpkg -S "${r#/usr}" &>/dev/null; }
  sec()  { echo -e "\n######## $* ########" >> "$P"; }
  flag() { warn "$*"; echo "[SUSPICIOUS] $*" >> "$P"; }
  # scan files: dump non-comment lines to the report, flag suspicious ones
  scan() {
    local f
    for f in "$@"; do
      [[ -f $f ]] || continue
      echo "--- $f" >> "$P"
      grep -vE '^\s*(#|$)' "$f" 2>/dev/null >> "$P"
      while IFS= read -r line; do flag "$f: $line"; done \
        < <(grep -vE '^\s*#' "$f" 2>/dev/null | grep -E "$SUS")
    done
  }

  echo "Checking cron / at / timers..."
  sec "CRON"
  scan /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
       /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*
  for f in /var/spool/cron/crontabs/*; do [[ -f $f ]] && warn "user crontab exists: $(basename "$f") - review it"; done
  sec "AT JOBS"
  if command -v atq >/dev/null; then atq >> "$P"; [[ -n $(atq) ]] && flag "pending 'at' jobs: $(atq | wc -l) (see atq / at -c <id>)"; fi
  scan /var/spool/cron/atjobs/*
  sec "SYSTEMD TIMERS"; systemctl list-timers --all --no-pager >> "$P"

  echo "Checking systemd services..."
  sec "CUSTOM SYSTEMD UNITS"
  while IFS= read -r f; do
    scan "$f"
    owned "$f" || flag "unit not from any package: $f ($(grep -hE '^Exec' "$f" | head -2 | xargs))"
  done < <( { find /etc/systemd/system /etc/systemd/user -maxdepth 2 -type f \
               \( -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.socket' \) 2>/dev/null
             find /lib/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f \
               -newermt "$PERSIST_DAYS days ago" 2>/dev/null; } | sort -u)
  for h in $HOMES; do
    for f in "$h"/.config/systemd/user/*; do [[ -f $f ]] && { flag "per-user systemd unit: $f"; scan "$f"; }; done
  done

  echo "Checking shell startup files..."
  sec "SHELL STARTUP"
  scan /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment /etc/zsh/zshrc
  for h in $HOMES; do
    scan "$h"/.bashrc "$h"/.profile "$h"/.bash_profile "$h"/.bash_login "$h"/.bash_logout "$h"/.zshrc
    grep -hE '^\s*alias\s+(sudo|ls|cd|su|passwd|ssh)=' "$h"/.bashrc "$h"/.bash_aliases 2>/dev/null \
      | grep -vE "alias\s+([a-z]+)='\1( +-[-a-zA-Z=]+)*'\s*$" | while IFS= read -r l; do flag "$h: hijacking alias: $l"; done
  done

  echo "Checking boot / login / package hooks..."
  sec "RC.LOCAL / INIT.D"
  scan /etc/rc.local
  find /etc/init.d -type f -newermt "$PERSIST_DAYS days ago" 2>/dev/null | while read -r f; do flag "recently changed init script: $f"; done
  sec "MOTD SCRIPTS"; scan /etc/update-motd.d/*
  sec "APT HOOKS"
  grep -rHE 'Invoke|Pre-Install-Pkgs' /etc/apt/apt.conf.d 2>/dev/null | tee -a "$P" \
    | grep -E "$SUS" | while IFS= read -r l; do flag "APT hook: $l"; done
  sec "UDEV RULES"
  grep -rH 'RUN' /etc/udev/rules.d 2>/dev/null | tee -a "$P" | while IFS= read -r l; do flag "udev RUN rule: $l"; done
  sec "AUTOSTART"
  for f in /etc/xdg/autostart/*.desktop; do [[ -f $f ]] && ! owned "$f" && flag "autostart not from a package: $f"; done
  for h in $HOMES; do for f in "$h"/.config/autostart/*; do [[ -f $f ]] && { flag "user autostart: $f"; scan "$f"; }; done; done
  sec "PAM"
  grep -rHE 'pam_exec|pam_script' /etc/pam.d 2>/dev/null | while IFS= read -r l; do flag "PAM runs a command: $l"; done
  for d in $(readlink -f /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security 2>/dev/null | sort -u); do
    for m in "$d"/*.so; do [[ -f $m ]] && ! owned "$m" && flag "PAM module not from any package: $m"; done
  done
  sec "LD PRELOAD"
  [[ -s /etc/ld.so.preload ]] && { flag "/etc/ld.so.preload: $(xargs < /etc/ld.so.preload)"; }
  grep -rl 'LD_PRELOAD' /etc/environment /etc/profile.d 2>/dev/null | while read -r f; do flag "LD_PRELOAD set in $f"; done

  echo "Checking SSH keys and sudo..."
  sec "SSH"
  for h in $HOMES; do
    for k in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do
      [[ -s $k ]] && { echo "--- $k" >> "$P"; cat "$k" >> "$P"; warn "$k has $(grep -c . "$k") key(s) - remove any you don't recognise"; }
    done
    [[ -f $h/.ssh/rc ]] && { flag "$h/.ssh/rc runs on every SSH login"; scan "$h/.ssh/rc"; }
  done
  [[ -f /etc/ssh/sshrc ]] && { flag "/etc/ssh/sshrc runs on every SSH login"; scan /etc/ssh/sshrc; }
  grep -hE '^\s*(AuthorizedKeysFile|AuthorizedKeysCommand|ForceCommand|PermitUserEnvironment)' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | while IFS= read -r l; do flag "sshd: $l"; done
  sec "SUDOERS"
  grep -rhE 'NOPASSWD|^\s*[^#%].*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | tee -a "$P" \
    | grep NOPASSWD | while IFS= read -r l; do flag "sudo without password: $l"; done

  echo "Checking running processes..."
  sec "PROCESSES"
  for pdir in /proc/[0-9]*; do
    exe=$(readlink "$pdir/exe" 2>/dev/null) || continue
    case "$exe" in
      *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*)
        flag "PID ${pdir#/proc/} running from $exe : $(tr '\0' ' ' < "$pdir/cmdline" | cut -c1-120)" ;;
    esac
  done
  ss -tupn state established 2>/dev/null >> "$P"
  ss -tlpn 2>/dev/null | grep -E 'users:\(\("(nc|ncat|socat|python[0-9.]*|perl|ruby|php|bash|sh|dash)"' | while IFS= read -r l; do flag "odd listener: $l"; done

  echo "Checking recently changed files (last $PERSIST_DAYS days)..."
  sec "RECENTLY MODIFIED (excluding logs/caches)"
  timeout 45 find /etc /usr/local /opt /usr/bin /usr/sbin /bin /sbin /root /var/spool -xdev -type f \
    -newermt "$PERSIST_DAYS days ago" 2>/dev/null | grep -vE '/(ld.so.cache|mtab|resolv.conf)$|/etc/(ssh|sysctl.d|ufw)/|/root/harden-' >> "$P"
  find /tmp /dev/shm /var/tmp -xdev -type f \( -perm -u+x -o -name '.*' \) 2>/dev/null \
    | grep -vE '/\.X[0-9]+-lock$' | while read -r f; do flag "executable or hidden file in temp dir: $f"; done

  echo "Verifying system binaries against packages (up to 2 min)..."
  sec "DPKG VERIFY (binaries changed since install)"
  timeout 120 dpkg --verify 2>/dev/null | awk '$2!="c"' | grep -E '^..5' | tee -a "$P" \
    | grep -E ' /(usr/)?(s)?bin/| /lib/| /usr/lib/' | while IFS= read -r l; do flag "modified package file: $l"; done

  echo
  HITS=$(grep -c '^\[SUSPICIOUS\]' "$P")
  echo "Persistence hunt done: $HITS suspicious item(s). Full report: $P"
  [[ $HITS -gt 0 ]] && warn "Review the yellow lines above before trusting this box."
fi

# ---------- 3. Accounts ----------
ACCT_MSG="Locks these accounts so nobody can log in with them:
  - accounts with NO password:      ${EMPTY:-none found}
  - extra admin (UID 0) accounts:   ${UID0:-none found}
  - the root password (you keep admin access through sudo)"
if [[ -n $AUTHORIZED_USERS ]]; then
  ACCT_MSG+="
  - users not in your authorized list will be $([[ $LOCK_UNAUTHORIZED == 1 ]] && echo LOCKED || echo 'listed only, not locked')"
fi
if step "Lock risky accounts" "$ACCT_MSG"; then
  for u in $EMPTY; do run "passwd -l '$u'"; done
  for u in $UID0;  do warn "locking UID-0 impostor $u"; run "usermod -L -s /usr/sbin/nologin '$u'"; done
  run "passwd -l root"
  if [[ -n $AUTHORIZED_USERS ]]; then
    for u in $(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/{print $1}' /etc/passwd); do
      if ! grep -qw "$u" <<<"$AUTHORIZED_USERS"; then
        warn "user not on authorized list: $u"
        [[ $LOCK_UNAUTHORIZED == 1 ]] && run "usermod -L -s /usr/sbin/nologin '$u'"
      fi
    done
  fi
fi

# ---------- 3b. Password changes ----------
PW_USERS=$(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/{print $1}' /etc/passwd | xargs)
if [[ -n $PW_USERS ]] && step "Change user passwords" \
"Goes through each user who can log in, one at a time:
  $PW_USERS
For each one you choose: type a new password yourself, have one
generated, or skip that user. Passwords are never written to the log.
WARNING: if a scored service logs in as one of these users (for example
an FTP account), changing it can break scoring unless you report the new
password to the competition. Root is skipped - it was locked in step 3."; then
  genpw() { tr -dc 'A-Za-z0-9@#%+=' </dev/urandom 2>/dev/null | head -c 16; }
  for u in $PW_USERS; do
    while true; do
      printf "\nUser '%s': [c]hange (type it) / [g]enerate / [s]kip / [d]one with passwords: " "$u" >/dev/tty
      read -r a </dev/tty
      case "${a,,}" in
        c)
          if [[ $DRY_RUN == 1 ]]; then echo "[dry-run] would run: passwd $u"; break; fi
          # talk straight to the terminal so nothing lands in the log
          if passwd "$u" </dev/tty >/dev/tty 2>&1; then echo "Password changed for $u"; break
          else echo "passwd failed for $u - try again or skip" >/dev/tty; fi ;;
        g)
          if [[ $DRY_RUN == 1 ]]; then echo "[dry-run] would set a generated password for $u"; break; fi
          p=$(genpw)
          if echo "$u:$p" | chpasswd; then
            echo "Password changed for $u (generated)"
            printf "  >>> %s : %s   <- write this down now, it is NOT saved anywhere\n" "$u" "$p" >/dev/tty
            printf "  Press Enter once you've recorded it... " >/dev/tty; read -r _ </dev/tty
            clear >/dev/tty 2>/dev/null || printf '\n%.0s' {1..40} >/dev/tty
          else echo "chpasswd failed for $u"; fi
          unset p; break ;;
        s) echo "Skipped password for $u"; echo "SKIPPED password: $u" >> "$OUT/skipped.txt"; break ;;
        d) echo "Done with passwords"; break 2 ;;
        *) echo "Please type c, g, s or d." >/dev/tty ;;
      esac
    done
  done
fi

# ---------- 4. SSH ----------
if [[ -f /etc/ssh/sshd_config ]] && step "Harden SSH" \
"Adds /etc/ssh/sshd_config.d/00-harden.conf which: blocks root login over
SSH, blocks empty passwords, allows 3 password tries, turns off X11/agent/
port forwarding, and drops idle sessions after ~10 min. The config is
tested first; SSH only restarts if the test passes. Your current SSH
session will stay connected."; then
  grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || \
    run "sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config"
  mkdir -p /etc/ssh/sshd_config.d
  # 00- prefix: sshd uses the FIRST value it reads, so this file wins
  run "cat > /etc/ssh/sshd_config.d/00-harden.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF"
  if [[ $DRY_RUN == 1 ]] || sshd -t; then
    run "systemctl restart ssh"
  else
    warn "sshd -t failed - removing drop-in, ssh NOT restarted"
    rm -f /etc/ssh/sshd_config.d/00-harden.conf
  fi
fi

# ---------- 5. Firewall ----------
FW_MSG="Turns on the ufw firewall: blocks ALL incoming connections except
these ports: $ALLOWED_PORTS
Outgoing traffic stays allowed. Any service on a port NOT listed above
will stop being reachable from other machines."
[[ $HAS_DOCKER == 1 ]] && FW_MSG+="
Docker host: existing rules are NOT reset, and container ports are not
affected by ufw (Docker bypasses it)."
if command -v ufw >/dev/null; then
  if step "Enable firewall" "$FW_MSG"; then
    [[ $HAS_DOCKER == 1 ]] || run "ufw --force reset >/dev/null"
    run "ufw default deny incoming"
    run "ufw default allow outgoing"
    for p in $ALLOWED_PORTS; do run "ufw allow $p"; done
    run "ufw logging on"
    run "ufw --force enable"
    ufw status verbose
  fi
else
  warn "ufw not installed (apt install ufw) - firewall step skipped"
fi

# ---------- 6. Kernel / sysctl ----------
if step "Kernel network and memory protections" \
"Writes /etc/sysctl.d/99-harden.conf and applies it now. It turns on
SYN-flood protection, ignores spoofed/redirected packets, logs strange
packets, and hides kernel memory info from normal users. Does not
interrupt running services."; then
  run "cat > /etc/sysctl.d/99-harden.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF"
  run "sysctl --system >/dev/null" && echo "applied"
fi

# ---------- 7. File permissions ----------
if step "Fix permissions on critical files" \
"Sets the correct owner and permissions on /etc/passwd, /etc/group,
/etc/shadow, /etc/gshadow, /etc/sudoers and /root, so password hashes
and admin settings can't be read or edited by normal users."; then
  run "chown root:root /etc/passwd /etc/group && chmod 644 /etc/passwd /etc/group"
  run "chown root:shadow /etc/shadow /etc/gshadow && chmod 640 /etc/shadow /etc/gshadow"
  run "chmod 440 /etc/sudoers"
  run "chmod 700 /root"
fi

# ---------- 8. Flavor-specific ----------
if [[ $FLAVOR == desktop ]]; then
  if step "Desktop: disable auto-login and guest" \
"Turns off automatic login and the guest account on the login screen.
Also lists (but does not stop) avahi and printer discovery if enabled.
Takes effect at the next login screen; current session is unaffected."; then
    if [[ -f /etc/gdm3/custom.conf ]]; then
      run "sed -i 's/^\s*AutomaticLoginEnable\s*=.*/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf"
    fi
    if [[ -d /etc/lightdm ]]; then
      mkdir -p /etc/lightdm/lightdm.conf.d
      run "printf '[Seat:*]\nallow-guest=false\nautologin-user=\n' > /etc/lightdm/lightdm.conf.d/50-harden.conf"
    fi
    for s in avahi-daemon cups-browsed; do
      systemctl is-enabled "$s" &>/dev/null && warn "$s enabled - disable if unneeded: systemctl disable --now $s"
    done
  fi
else
  if step "Server: check for risky services" \
"Lists telnet, rsh and avahi if they are enabled. Read-only - it only
tells you the command to turn them off, it doesn't stop anything."; then
    for s in telnet.socket rsh.socket avahi-daemon; do
      systemctl is-enabled "$s" &>/dev/null && warn "$s enabled - disable if unneeded: systemctl disable --now $s"
    done
  fi
fi

# ---------- 8a. Docker (IRC box) - audit only ----------
if [[ $HAS_DOCKER == 1 ]] && step "Docker audit (IRC)" \
"Backs up every docker compose file into $OUT, then lists running
containers and their published ports and warns about dangerous settings
(privileged, host networking, docker.sock mounts, Docker API on TCP).
Read-only: no container is stopped or restarted."; then
  docker compose ls 2>/dev/null
  docker compose ls --format json 2>/dev/null | grep -o '"ConfigFiles":"[^"]*"' | cut -d'"' -f4 \
    | tr ',' '\n' | while read -r f; do [[ -f $f ]] && cp --parents "$f" "$OUT/" && echo "backed up $f"; done
  echo; docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
  warn "Published ports above BYPASS ufw. Bind them deliberately in the compose file"
  warn "  (e.g. keep 6697 TLS, drop plaintext 6667 if scoring allows) - don't rely on ufw here."
  for id in $(docker ps -q); do
    n=$(docker inspect -f '{{.Name}}' "$id")
    [[ $(docker inspect -f '{{.HostConfig.Privileged}}' "$id") == true ]] && warn "$n runs PRIVILEGED"
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id") == host ]] && warn "$n uses host networking"
    docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$id" | grep -q docker.sock \
      && warn "$n mounts docker.sock (= root on host)"
    docker inspect -f '{{.Config.User}}' "$id" | grep -qE '^(|root|0)$' && echo "  $n runs as root inside container"
  done
  echo "docker group (root-equivalent!): $(getent group docker | cut -d: -f4)"
  ls -l /var/run/docker.sock
  ss -tlnp | grep -qE ':237[56]\b' && warn "Docker API is listening on TCP 2375/2376 - close it!"
  [[ -f /etc/docker/daemon.json ]] && { echo "daemon.json:"; cat /etc/docker/daemon.json; }
fi

# ---------- 8b. vsftpd (FTP box) ----------
if [[ $HAS_VSFTPD == 1 ]] && step "Harden vsftpd (FTP)" \
"Edits /etc/vsftpd.conf (original saved to $OUT) to:
  - $([[ $FTP_ANON == 1 ]] && echo 'KEEP anonymous login (FTP_ANON=1), but block anonymous uploads' || echo 'turn OFF anonymous login')
  - lock users inside their home folders
  - hide file owners, turn on transfer logging, set a warning banner
  - limit 5 connections per IP
  - use passive ports $PASV_MIN-$PASV_MAX (opened by the firewall step)
  - stop root logging in over FTP
Upload permission (write_enable) is left alone. vsftpd is restarted; if
it fails to start, the original config is put back automatically."; then
  F=/etc/vsftpd.conf
  cp "$F" "$OUT/vsftpd.conf.orig"
  setkv() {  # set key=value, replacing commented or existing lines
    if grep -qE "^\s*#?\s*$1=" "$F"; then run "sed -i -E 's|^\s*#?\s*$1=.*|$1=$2|' $F"
    else run "echo '$1=$2' >> $F"; fi
  }
  [[ $FTP_ANON == 1 ]] && setkv anonymous_enable YES || setkv anonymous_enable NO
  setkv anon_upload_enable NO
  setkv anon_mkdir_write_enable NO
  setkv local_enable YES
  setkv chroot_local_user YES
  setkv allow_writeable_chroot YES
  setkv local_umask 022
  setkv hide_ids YES
  setkv xferlog_enable YES
  setkv log_ftp_protocol YES
  setkv ftpd_banner "Authorized use only."
  setkv max_per_ip 5
  setkv pasv_enable YES
  setkv pasv_min_port "$PASV_MIN"
  setkv pasv_max_port "$PASV_MAX"
  grep -qx root /etc/ftpusers 2>/dev/null || run "echo root >> /etc/ftpusers"
  if [[ $DRY_RUN != 1 ]]; then
    systemctl restart vsftpd; sleep 1
    if systemctl is-active --quiet vsftpd; then echo "vsftpd restarted OK"
    else warn "vsftpd failed to start - restoring original config"
         cp "$OUT/vsftpd.conf.orig" "$F"; systemctl restart vsftpd; fi
  fi
  echo "FTP users with login shells:"; awk -F: '$3>=1000 && $7!~/nologin|false/{print "  "$1}' /etc/passwd
fi

# ---------- 9. Quick SUID sweep ----------
if step "Look for suspicious SUID programs" \
"Searches the disk (up to 60 seconds) for programs that run as root
from unusual folders - a common backdoor. Read-only, results saved to
$OUT/odd-suid.txt."; then
  timeout 60 find / -xdev -perm -4000 -type f 2>/dev/null \
    | grep -vE '^/(usr/)?(s)?bin/|^/usr/lib/|^/usr/libexec/|^/snap/' | tee "$OUT/odd-suid.txt"
fi

# ---------- Done ----------
c "Done. Next, by hand:"
[[ -s $OUT/skipped.txt ]] && { echo "Steps you skipped:"; sed 's/^/  /' "$OUT/skipped.txt"; echo; }
cat <<EOF
  1. Change passwords for anyone skipped above, and for service accounts the script can't see
     (database users, web app admins, Wazuh dashboard admin) - check scoring rules first
  2. Review $OUT/baseline.txt - cron, timers, authorized_keys, listening ports
  3. Verify scored services still respond from another box
       FTP:  ftp <ip>  (log in, ls - tests passive mode through the firewall)
       IRC:  nc -zv <ip> 6667 ; openssl s_client -connect <ip>:6697
       Docker: remove unneeded users from the 'docker' group (it is root)
  4. apt update && apt upgrade when you have time
  Rollback: tar xzf $OUT/etc-backup.tgz -C /
EOF
