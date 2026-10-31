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
# IRSeC 2026 rule notes (Blue Team Packet V2) - defaults are set to comply:
#   R6   whiteteam is never locked, re-passworded or restricted; admin rights checked at the end
#   R10  scored services (FTP on garage, IRC/Docker on grandstand, SSH on pitlane)
#        are AUDITED ONLY - their config is not changed unless you opt in
#   R14  out of scope, always allowed through the firewall and never touched:
#        172.16.1.0/24 mgmt, 10.X.1.99 NetBird egress, Datadog (us5 list),
#        dd-agent/ddagentuser, datadog* services/files, barrier->timing 514
#   R15  NO subnet blocking: the firewall does NOT default-deny unless you set
#        FW_DEFAULT_DENY=1 after getting White/Black Team approval.
#        Single attacker IPs can be blocked with BLOCK_IPS="1.2.3.4 5.6.7.8"
#   R7   run only during Hands-On periods.  R18: test before the competition.
#   R20  host this script at a public, unauthenticated link (e.g. public GitHub).
#   R23/24  no AI agents on competition boxes; fetch this from the competitor machine.

set -uo pipefail

########################## CONFIG ##########################
ALLOWED_PORTS="${ALLOWED_PORTS:-22/tcp}"      # extra ports to allow, e.g. "22/tcp 80/tcp"
# Local users from the packet (+ whiteteam). Anyone else with a login shell is reported.
AUTHORIZED_USERS="${AUTHORIZED_USERS:-whiteteam scrutineer techdirector crewchief firecrew jackcrew garagecrew celebrity pitlaner reserve gunners}"
AUTHORIZED_ADMINS="${AUTHORIZED_ADMINS:-whiteteam scrutineer techdirector crewchief firecrew}"
# R6 / R14: accounts the script must NEVER lock, re-password or restrict
PROTECTED_USERS="${PROTECTED_USERS:-whiteteam dd-agent ddagentuser}"

TEAM="${TEAM:-}"                              # team number X; blank = worked out from this box's IP
MGMT_NETS="${MGMT_NETS:-172.16.1.0/24}"       # R14b-i management network (out of scope)
WAZUH_SYSLOG_FROM="${WAZUH_SYSLOG_FROM:-any}" # R14b-vii: barrier->timing 514 must never be blocked
WAZUH_MANAGER="${WAZUH_MANAGER:-}"            # timing IP, for agent boxes (blank = 192.168.X.4)
NETBIRD_PORT="${NETBIRD_PORT:-51820}"         # NetBird WireGuard UDP port
NETBIRD_IF="${NETBIRD_IF:-wt0}"               # NetBird tunnel interface
DD_RANGES="${DD_RANGES:-}"                    # Datadog CIDRs; blank = download list below
DD_SITE_URL="${DD_SITE_URL:-https://ip-ranges.us5.datadoghq.com/}"  # R14b-vi official list
FW_DEFAULT_DENY="${FW_DEFAULT_DENY:-0}"       # R15: 1 ONLY with White/Black Team approval
BLOCK_IPS="${BLOCK_IPS:-}"                    # R15: single attacker IPs to block (no subnets)
LOCK_UNAUTHORIZED="${LOCK_UNAUTHORIZED:-0}"   # 1 = lock login users not in the list above
DRY_RUN="${DRY_RUN:-0}"
CONFIRM="${CONFIRM:-1}"                       # 0 = don't ask before each step
FTP_HARDEN="${FTP_HARDEN:-0}"                 # R10: 1 = change vsftpd.conf (get approval first)
FTP_ANON="${FTP_ANON:-keep}"                  # with FTP_HARDEN=1: keep | off
SSH_HARDEN="${SSH_HARDEN:-auto}"              # R10: auto = skip on Debian (pitlane SSH is scored)
############################################################
# Ports for detected roles are added automatically:
#   Wazuh manager -> 443 1514 1515 55000/tcp, plus 514 tcp/udp (syslog)
#   vsftpd        -> 21/tcp + the passive range already in vsftpd.conf
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
    read -r ans </dev/tty || { echo "No terminal to ask on - re-run with CONFIRM=0 to skip prompts."; exit 1; }
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
# FTP: use the passive range that is ALREADY configured (R10 - don't change the service)
PASV_RANGE=""
if [[ $HAS_VSFTPD == 1 ]]; then
  ALLOWED_PORTS+=" 21/tcp"
  pmin=$(grep -E '^\s*pasv_min_port=' /etc/vsftpd.conf | tail -1 | cut -d= -f2 | tr -d ' ')
  pmax=$(grep -E '^\s*pasv_max_port=' /etc/vsftpd.conf | tail -1 | cut -d= -f2 | tr -d ' ')
  [[ -n $pmin && -n $pmax ]] && PASV_RANGE="$pmin:$pmax/tcp" && ALLOWED_PORTS+=" $PASV_RANGE"
fi
ALLOWED_PORTS=$(tr ' ' '\n' <<<"$ALLOWED_PORTS" | awk 'NF && !s[$0]++' | xargs)

# in_list <word> <list> -> exact word match (so "dd" does not match "dd-agent")
in_list() { local w; for w in $2; do [[ $w == "$1" ]] && return 0; done; return 1; }
is_protected() { in_list "$1" "$PROTECTED_USERS"; }
# drop protected users from a space-separated list
unprotect() { local u o=""; for u in $1; do is_protected "$u" || o+="$u "; done; echo "${o% }"; }
# lines mentioning out-of-scope things (R6/R14) are never reported as suspicious
OOS_RE='whiteteam|dd-agent|ddagentuser|datadog'

# Team number X from this box's own address (10.X.1.Y LAN or 192.168.X.Y cloud)
if [[ -z $TEAM ]]; then
  for a in $(hostname -I 2>/dev/null); do
    if   [[ $a =~ ^10\.([0-9]+)\.1\.[0-9]+$ ]];     then TEAM=${BASH_REMATCH[1]}; break
    elif [[ $a =~ ^192\.168\.([0-9]+)\.[0-9]+$ ]]; then TEAM=${BASH_REMATCH[1]}; break; fi
  done
fi
NETBIRD_EGRESS=""; BARRIER=""
if [[ -n $TEAM ]]; then
  NETBIRD_EGRESS="10.$TEAM.1.99"              # R14b-ii: never modify/block
  BARRIER="10.$TEAM.1.254"                    # R14b-vii: barrier syslog-ng -> timing 514
  [[ -z $WAZUH_MANAGER ]] && WAZUH_MANAGER="192.168.$TEAM.4"
fi
# Every out-of-scope address the firewall must allow (R14/R15a)
OOS_ALLOW="$MGMT_NETS $NETBIRD_EGRESS $BARRIER"

UID0=$(unprotect "$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | xargs)")
EMPTY=$(unprotect "$(awk -F: '$2==""{print $1}' /etc/shadow | xargs)")

c "$ID $VER ($FLAVOR)  team=${TEAM:-?}  docker=$HAS_DOCKER vsftpd=$HAS_VSFTPD wazuh=$HAS_WAZUH  dry_run=$DRY_RUN"
echo "Log for this run: $LOG"
[[ -z $TEAM ]] && warn "Could not work out the team number from this box's IP - set TEAM=<X> so NetBird egress (10.X.1.99) and barrier are allowed"
[[ $ID != ubuntu ]] && warn "This is $ID, not Ubuntu. On pitlane (Debian) SSH is a SCORED service - SSH step will be skipped."
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
Anything about whiteteam or Datadog is labelled OUT OF SCOPE (rules 6/14)
and must be left alone. Full report: $OUT/persistence.txt - keep it as
evidence for the Incident Response Report. Nothing is deleted or disabled."; then
  P="$OUT/persistence.txt"; : > "$P"
  HOMES=$(awk -F: '($3==0 || $3>=1000) && $3<65534 {print $6}' /etc/passwd | sort -u)

  owned() { local r; r=$(readlink -f "$1")
            dpkg -S "$1" &>/dev/null || dpkg -S "$r" &>/dev/null || dpkg -S "${r#/usr}" &>/dev/null; }
  sec()  { echo -e "\n######## $* ########" >> "$P"; }
  # R6/R14: anything about whiteteam or Datadog is labelled out of scope, not suspicious
  flag() {
    if grep -qiE "$OOS_RE" <<<"$*"; then
      echo "  (out of scope - do NOT touch) $*"; echo "[OUT-OF-SCOPE] $*" >> "$P"
    else warn "$*"; echo "[SUSPICIOUS] $*" >> "$P"; fi
  }
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
      [[ -s $k ]] || continue
      echo "--- $k" >> "$P"; cat "$k" >> "$P"
      if grep -qiE "$OOS_RE" <<<"$k"; then echo "  $k: $(grep -c . "$k") key(s) - OUT OF SCOPE, do not touch"
      else warn "$k has $(grep -c . "$k") key(s) - review; don't remove any White Team gave you"; fi
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
  - the root password (you keep admin access through sudo)
Never touched: $PROTECTED_USERS"
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
      is_protected "$u" && continue
      if ! in_list "$u" "$AUTHORIZED_USERS"; then
        warn "user not on authorized list: $u"
        [[ $LOCK_UNAUTHORIZED == 1 ]] && run "usermod -L -s /usr/sbin/nologin '$u'"
      fi
    done
  fi
  # Report (don't change) admins that aren't on the packet's admin list
  for g in sudo admin wheel docker; do
    for u in $(getent group "$g" | cut -d: -f4 | tr ',' ' '); do
      is_protected "$u" && continue
      in_list "$u" "$AUTHORIZED_ADMINS" || warn "'$u' is in the $g group but is not a listed admin - review (not changed)"
    done
  done
fi

# ---------- 3b. Password changes ----------
PW_USERS=$(unprotect "$(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/{print $1}' /etc/passwd | xargs)")
if [[ -n $PW_USERS ]] && step "Change user passwords" \
"Goes through each user who can log in, one at a time:
  $PW_USERS
For each one you choose: type a new password yourself, have one
generated, or skip that user. Passwords are never written to the log.
WARNING: if a scored check logs in as one of these users (for example an
FTP account), changing it breaks scoring. The packet gives no process for
reporting new passwords - ask White Team before changing those accounts. Root is skipped - it was locked earlier.
Never touched: $PROTECTED_USERS"; then
  genpw() { tr -dc 'A-Za-z0-9@#%+=' </dev/urandom 2>/dev/null | head -c 16; }
  for u in $PW_USERS; do
    while true; do
      printf "\nUser '%s': [c]hange (type it) / [g]enerate / [s]kip / [d]one with passwords: " "$u" >/dev/tty
      read -r a </dev/tty 2>/dev/null || { warn "No terminal - password changes skipped"; break 2; }
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
[[ $SSH_HARDEN == auto ]] && { [[ $ID == ubuntu ]] && SSH_HARDEN=1 || SSH_HARDEN=0; }
[[ $SSH_HARDEN != 1 && -f /etc/ssh/sshd_config ]] && \
  warn "SSH step skipped: SSH is a scored service on this box type (rule 10). Set SSH_HARDEN=1 only with White Team approval."
if [[ $SSH_HARDEN == 1 && -f /etc/ssh/sshd_config ]] && step "Harden SSH" \
"Adds /etc/ssh/sshd_config.d/00-harden.conf which: blocks root login over
SSH, blocks empty passwords, allows 3 password tries, turns off X11/agent/
port forwarding, and drops connections that stop responding. Password
logins stay ON (whiteteam and scoring may use them). The config is tested
first; SSH only restarts if the test passes. Your current SSH session
stays connected. SSH is not a scored service on the Ubuntu boxes."; then
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
# R14/R15: allow everything out of scope, block ONLY single IPs, no subnet blocking
UFW_ACTIVE=0; ufw status 2>/dev/null | grep -q 'Status: active' && UFW_ACTIVE=1
FW_MSG="Adds ufw firewall rules WITHOUT wiping existing ones (current rules are
saved to $OUT first). Allow rules for out-of-scope traffic (rule 14):
  - management net + NetBird egress + barrier, all ports: ${OOS_ALLOW:-none (set TEAM)}
  - NetBird: $NETBIRD_PORT/udp and everything on the $NETBIRD_IF tunnel
  - Datadog us5 ranges: ${DD_RANGES:+given by you}${DD_RANGES:-downloaded from $DD_SITE_URL}"
[[ $HAS_WAZUH == 1 ]] && FW_MSG+="
  - Wazuh/timing syslog 514 udp+tcp from $WAZUH_SYSLOG_FROM (barrier -> timing must flow)"
FW_MSG+="
  - service ports: $ALLOWED_PORTS"
[[ -n $BLOCK_IPS ]] && FW_MSG+="
Blocks these single IPs (rule 15 allows individual IPs only): $BLOCK_IPS
  Out-of-scope or own-team addresses are refused automatically."
if [[ $FW_DEFAULT_DENY == 1 ]]; then
  FW_MSG+="
DEFAULT-DENY IS ON (FW_DEFAULT_DENY=1): all other incoming traffic will be
blocked. Rule 15 forbids blocking subnets - only do this if White/Black
Team has explicitly approved it."
elif [[ $UFW_ACTIVE == 1 ]]; then
  FW_MSG+="
ufw is already active: its current default policy is left as it is."
else
  FW_MSG+="
Incoming default stays ALLOW (rule 15: no subnet blocking), so turning ufw
on will not cut anything off. It mainly gives you logging + IP blocks."
fi
[[ $HAS_DOCKER == 1 ]] && FW_MSG+="
Docker host: container ports are not affected by ufw (Docker bypasses it)."

if command -v ufw >/dev/null; then
  if step "Firewall rules (compliant mode)" "$FW_MSG"; then
    ufw status numbered > "$OUT/ufw-before.txt" 2>&1
    iptables-save > "$OUT/iptables-before.txt" 2>/dev/null
    echo "saved current rules to $OUT/ufw-before.txt and iptables-before.txt"
    CIDR_RE='^[0-9a-fA-F:.]+(/[0-9]{1,3})?$'

    # 1) Out-of-scope hosts/nets: mgmt, NetBird egress, barrier
    for n in $OOS_ALLOW; do
      if [[ $n =~ $CIDR_RE ]]; then run "ufw allow from $n comment 'out-of-scope (rule 14)'"
      else warn "not a valid IP/CIDR, skipped: $n"; fi
    done
    [[ -z $NETBIRD_EGRESS ]] && warn "Team number unknown - NetBird egress 10.X.1.99 NOT allowed. Re-run with TEAM=<X>"

    # 2) NetBird
    run "ufw allow $NETBIRD_PORT/udp comment 'netbird wireguard'"
    run "ufw allow in on $NETBIRD_IF comment 'netbird tunnel'"

    # 3) Wazuh / timing syslog 514
    if [[ $HAS_WAZUH == 1 ]]; then
      if [[ $WAZUH_SYSLOG_FROM == any ]]; then
        run "ufw allow 514/udp comment 'wazuh syslog'"; run "ufw allow 514/tcp comment 'wazuh syslog'"
      else
        for n in $WAZUH_SYSLOG_FROM $BARRIER; do
          run "ufw allow proto udp from $n to any port 514 comment 'wazuh syslog'"
          run "ufw allow proto tcp from $n to any port 514 comment 'wazuh syslog'"
        done
      fi
    elif [[ -n $WAZUH_MANAGER ]]; then
      run "ufw allow out to $WAZUH_MANAGER port 514 comment 'wazuh syslog'"
      run "ufw allow out proto tcp to $WAZUH_MANAGER port 1514,1515 comment 'wazuh agent'"
    fi

    # 4) Datadog (in AND out must never be blocked)
    if [[ -z $DD_RANGES ]]; then
      echo "Downloading Datadog IP ranges from $DD_SITE_URL ..."
      DD_JSON=$( (curl -fsS --max-time 15 "$DD_SITE_URL" || wget -qO- --timeout=15 "$DD_SITE_URL") 2>/dev/null )
      if [[ -n $DD_JSON ]] && command -v python3 >/dev/null; then
        DD_RANGES=$(python3 -c '
import json,sys
d=json.loads(sys.stdin.read()); out=set()
for k,v in d.items():
    if isinstance(v,dict):
        out.update(v.get("prefixes_ipv4",[])); out.update(v.get("prefixes_ipv6",[]))
print(" ".join(sorted(out)))' <<<"$DD_JSON" 2>/dev/null)
      fi
      [[ -n $DD_RANGES ]] || warn "Could not get Datadog ranges (no internet?). Re-run with DD_RANGES=\"cidr cidr ...\""
    fi
    DD_COUNT=0
    for n in $DD_RANGES; do
      [[ $n =~ $CIDR_RE ]] || { warn "bad Datadog range skipped: $n"; continue; }
      run "ufw allow from $n comment 'datadog (rule 14)' >/dev/null" && \
      run "ufw allow out to $n comment 'datadog (rule 14)' >/dev/null" && DD_COUNT=$((DD_COUNT+1))
    done
    [[ $DD_COUNT -gt 0 ]] && echo "Added in+out rules for $DD_COUNT Datadog range(s)"

    # 5) Service ports
    for p in $ALLOWED_PORTS; do run "ufw allow $p"; done

    # 6) Single-IP blocks (rule 15) - refuse anything out of scope or in our own team nets
    if [[ -n $BLOCK_IPS ]]; then
      PROTECT_NETS="$OOS_ALLOW $DD_RANGES 127.0.0.0/8"
      [[ -n $TEAM ]] && PROTECT_NETS+=" 10.$TEAM.1.0/24 192.168.$TEAM.0/24"
      for ip in $BLOCK_IPS; do
        verdict=$(python3 - "$ip" "$PROTECT_NETS" <<'PY'
import ipaddress,sys
s=sys.argv[1]
try:
    if "/" in s and not s.endswith(("/32","/128")): print("SUBNET"); sys.exit()
    a=ipaddress.ip_address(s.split("/")[0])
except ValueError: print("INVALID"); sys.exit()
for n in sys.argv[2].split():
    try:
        if a in ipaddress.ip_network(n, strict=False): print("PROTECTED "+n); sys.exit()
    except ValueError: pass
print("OK")
PY
)
        case "$verdict" in
          OK)          run "ufw prepend deny from ${ip%/*} comment 'blocked attacker'" ;;
          SUBNET)      warn "refused $ip: subnets may not be blocked (rule 15)" ;;
          INVALID)     warn "refused $ip: not a valid IP" ;;
          PROTECTED*)  warn "refused $ip: inside out-of-scope/own-team range ${verdict#PROTECTED } (rules 14/15a)" ;;
        esac
      done
    fi

    # 7) Default policy
    if [[ $FW_DEFAULT_DENY == 1 ]]; then
      if [[ $HAS_VSFTPD == 1 && -z $PASV_RANGE ]]; then
        warn "vsftpd has no fixed passive port range - default deny would break scored FTP. Default policy NOT changed."
      else
        warn "Setting default DENY incoming (FW_DEFAULT_DENY=1) - make sure White/Black Team approved this"
        run "ufw default deny incoming"
      fi
    elif [[ $UFW_ACTIVE == 0 ]]; then
      run "ufw default allow incoming"
    fi
    run "ufw default allow outgoing"
    run "ufw logging on"
    run "ufw --force enable"
    ufw status verbose | tee "$OUT/ufw-after.txt" | head -40
    echo "(full rule list saved to $OUT/ufw-after.txt)"
  fi
else
  warn "ufw not installed - firewall step skipped (don't install software without checking it's allowed)"
fi

# ---------- 6. Kernel / sysctl ----------
if step "Kernel network and memory protections" \
"Writes /etc/sysctl.d/99-harden.conf and applies it now. It turns on
SYN-flood protection, ignores spoofed/redirected packets, logs strange
packets, and hides kernel memory info from normal users. Reverse-path
filtering is set to LOOSE (2) so NetBird, Docker and multi-interface
routing keep working (rule 14: NetBird traffic must not be blocked).
Does not interrupt running services."; then
  run "cat > /etc/sysctl.d/99-harden.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
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
  warn "Published ports above BYPASS ufw. Do NOT change the compose file, ports or"
  warn "  containers of the scored IRC service without White/Black Team approval (rule 10)."
  for id in $(docker ps -q); do
    n=$(docker inspect -f '{{.Name}}' "$id")
    [[ $(docker inspect -f '{{.HostConfig.Privileged}}' "$id") == true ]] && warn "$n runs PRIVILEGED"
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id") == host ]] && warn "$n uses host networking"
    docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$id" | grep -q docker.sock \
      && warn "$n mounts docker.sock (= root on host)"
    docker inspect -f '{{.Config.User}}' "$id" | grep -qE '^(|root|0)$' && echo "  $n runs as root inside container"
  done
  echo "docker group (root-equivalent!): $(getent group docker | cut -d: -f4)"
  echo "  (never remove whiteteam from it - rule 6)"
  ls -l /var/run/docker.sock
  ss -tlnp | grep -qE ':237[56]\b' && warn "Docker API is listening on TCP 2375/2376 - close it!"
  [[ -f /etc/docker/daemon.json ]] && { echo "daemon.json:"; cat /etc/docker/daemon.json; }
fi

# ---------- 8b. vsftpd (FTP box) - R10: audit by default ----------
if [[ $HAS_VSFTPD == 1 ]] && step "vsftpd (FTP) check$([[ $FTP_HARDEN == 1 ]] && echo ' + minimal hardening')" \
"FTP is a SCORED service (rule 10: don't change scored services from their
initial configuration without White/Black Team approval).
$(if [[ $FTP_HARDEN == 1 ]]; then echo "FTP_HARDEN=1 is set, so it will ALSO make these small changes
(original saved to $OUT, auto-restored if vsftpd fails to start):
  - block anonymous uploads / folder creation
  - turn on transfer logging and hide file owners
  - stop root logging in over FTP
  - anonymous login: $([[ $FTP_ANON == off ]] && echo 'turned OFF (FTP_ANON=off)' || echo 'left as it is')
Ports, passive range, chroot and upload rights are NOT changed."
else echo "Read-only: reports risky settings in /etc/vsftpd.conf and which users can
log in over FTP. Nothing is changed. Re-run with FTP_HARDEN=1 only after
White Team approves."; fi)"; then
  F=/etc/vsftpd.conf
  cp "$F" "$OUT/vsftpd.conf.orig"
  getkv() { grep -E "^\s*$1=" "$F" | tail -1 | cut -d= -f2- | tr -d ' '; }
  echo "Current settings:"
  for k in anonymous_enable anon_upload_enable anon_mkdir_write_enable write_enable local_enable \
           chroot_local_user xferlog_enable ssl_enable pasv_min_port pasv_max_port listen listen_ipv6; do
    printf "  %-24s %s\n" "$k" "$(getkv $k || true)"
  done
  [[ $(getkv anonymous_enable) == YES ]]   && warn "anonymous login is ON - check if scoring needs it before asking to turn it off"
  [[ $(getkv anon_upload_enable) == YES ]] && warn "anonymous UPLOAD is ON - attackers can drop files"
  [[ $(getkv xferlog_enable) == YES ]]     || warn "transfer logging is off - you'll have less evidence for the IR report"
  [[ -z $PASV_RANGE ]] && echo "  (no fixed passive range - fine while the firewall isn't default-deny)"
  if [[ $FTP_HARDEN == 1 ]]; then
    setkv() {  # set key=value, replacing commented or existing lines
      if grep -qE "^\s*#?\s*$1=" "$F"; then run "sed -i -E 's|^\s*#?\s*$1=.*|$1=$2|' $F"
      else run "echo '$1=$2' >> $F"; fi
    }
    [[ $FTP_ANON == off ]] && setkv anonymous_enable NO
    setkv anon_upload_enable NO
    setkv anon_mkdir_write_enable NO
    setkv xferlog_enable YES
    setkv log_ftp_protocol YES
    setkv hide_ids YES
    grep -qx root /etc/ftpusers 2>/dev/null || run "echo root >> /etc/ftpusers"
    if [[ $DRY_RUN != 1 ]]; then
      systemctl restart vsftpd; sleep 1
      if systemctl is-active --quiet vsftpd; then echo "vsftpd restarted OK"
      else warn "vsftpd failed to start - restoring original config"
           cp "$OUT/vsftpd.conf.orig" "$F"; systemctl restart vsftpd; fi
    fi
  fi
  echo "Users with login shells (can use FTP):"; awk -F: '$3>=1000 && $7!~/nologin|false/{print "  "$1}' /etc/passwd
fi

# ---------- 9. Quick SUID sweep ----------
if step "Look for suspicious SUID programs" \
"Searches the disk (up to 60 seconds) for programs that run as root
from unusual folders - a common backdoor. Read-only, results saved to
$OUT/odd-suid.txt."; then
  timeout 60 find / -xdev -perm -4000 -type f 2>/dev/null \
    | grep -vE '^/(usr/)?(s)?bin/|^/usr/lib/|^/usr/libexec/|^/snap/' | grep -viE "$OOS_RE" | tee "$OUT/odd-suid.txt"
fi

# ---------- 10. Rule 6 check: whiteteam must keep admin rights ----------
c "Rule 6 check: whiteteam"
if id whiteteam &>/dev/null; then
  wt_ok=1
  wt_hash=$(getent shadow whiteteam | cut -d: -f2)
  if [[ $wt_hash == '!$'* || $wt_hash == '!!$'* ]]; then
    warn "whiteteam's password is LOCKED - tell White Team (unlock: passwd -u whiteteam)"; wt_ok=0
  elif [[ $wt_hash =~ ^[!*]*$ ]]; then
    echo "  note: whiteteam has no password set (may log in with SSH keys) - not changed"
  fi
  usermod_exp=$(getent shadow whiteteam | cut -d: -f8)
  [[ -n $usermod_exp && $usermod_exp -le $(( $(date +%s) / 86400 )) ]] && { warn "whiteteam account is EXPIRED - tell White Team"; wt_ok=0; }
  sh=$(getent passwd whiteteam | cut -d: -f7)
  [[ $sh =~ (nologin|false)$ ]] && { warn "whiteteam has no login shell ($sh)"; wt_ok=0; }
  if ! id -nG whiteteam | grep -qwE 'sudo|admin|wheel' && ! sudo -l -U whiteteam 2>/dev/null | grep -q '(ALL'; then
    warn "whiteteam does NOT appear to have admin rights - contact White Team (rule 6)"; wt_ok=0
  fi
  [[ $wt_ok == 1 ]] && echo "whiteteam: present, unlocked, has admin rights - OK"
else
  warn "whiteteam user does not exist on this box - tell White Team (don't create it yourself: rule 5)"
fi

# ---------- Done ----------
c "Done. Next, by hand:"
[[ -s $OUT/skipped.txt ]] && { echo "Steps you skipped:"; sed 's/^/  /' "$OUT/skipped.txt"; echo; }
cat <<EOF
  1. Passwords: before changing any account a scored check logs in with (FTP users,
     MariaDB, etc.), ask White Team how to report the new password. Never touch
     whiteteam, dd-agent or ddagentuser.
  2. Review $OUT/persistence.txt and baseline.txt. Lines marked OUT-OF-SCOPE
     (whiteteam / Datadog) must be left alone. Keep these files as evidence
     for the Incident Response Report.
  3. Check the Hermes dashboard (scoring.irsec.club) that every service is still green.
  4. Don't upgrade or reconfigure scored service packages (vsftpd, docker, ssh on
     pitlane) without approval - rule 10.
  5. To block an attacker: re-run with BLOCK_IPS="a.b.c.d" (single IPs only, rule 15).
  Rollback: tar xzf $OUT/etc-backup.tgz -C /   (ufw rules before: $OUT/ufw-before.txt)
EOF
