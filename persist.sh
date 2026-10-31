#!/usr/bin/env bash
# persist.sh - READ-ONLY persistence/backdoor hunt. Works on Debian, Ubuntu, Rocky/RHEL.
# Changes nothing, deletes nothing. Run as root.
#
# From the Debian box (pitlane) against the Rocky box (scrutineering):
#   scp persist.sh USER@192.168.X.3:/tmp/
#   ssh -t USER@192.168.X.3 'sudo bash /tmp/persist.sh'
#   scp USER@192.168.X.3:/tmp/persist-*.txt .        # bring the report back
#
# Anything about whiteteam / Datadog is labelled OUT-OF-SCOPE (rules 6/14): leave it alone.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }

DAYS="${DAYS:-7}"
HOST=$(hostname -s)
P="/tmp/persist-$HOST-$(date +%Y%m%d-%H%M%S).txt"; : > "$P"; chmod 600 "$P"
OOS_RE='whiteteam|dd-agent|ddagentuser|datadog'
SUS='(/dev/(tcp|udp)/|\bnc(at)?\b.*\s-[a-z]*[ec]|bash -i|sh -i|mkfifo|socat|python[0-9.]* -c|perl -e|ruby -e|php -r|base64 (-d|--decode)|(curl|wget)[^|;]*\|\s*(ba)?sh|/tmp/|/dev/shm/|/var/tmp/|chmod ([ugoa]*[+]s|[0-7]?[2467][0-7]{3})|chattr|useradd|usermod|nohup|LD_PRELOAD)'

if command -v dpkg >/dev/null; then PKG=deb; else PKG=rpm; fi
owned() { local r; r=$(readlink -f "$1")
  if [[ $PKG == deb ]]; then dpkg -S "$1" &>/dev/null || dpkg -S "$r" &>/dev/null || dpkg -S "${r#/usr}" &>/dev/null
  else rpm -qf "$1" &>/dev/null || rpm -qf "$r" &>/dev/null; fi; }

warn() { echo -e "\e[1;33m[!] $*\e[0m"; }
sec()  { echo "== $* =="; echo -e "\n######## $* ########" >> "$P"; }
flag() {
  if grep -qiE "$OOS_RE" <<<"$*"; then echo "  (out of scope - do NOT touch) $*"; echo "[OUT-OF-SCOPE] $*" >> "$P"
  else warn "$*"; echo "[SUSPICIOUS] $*" >> "$P"; fi; }
scan() { local f line
  for f in "$@"; do [[ -f $f ]] || continue
    echo "--- $f" >> "$P"; grep -vE '^\s*(#|$)' "$f" 2>/dev/null >> "$P"
    while IFS= read -r line; do flag "$f: $line"; done < <(grep -vE '^\s*#' "$f" 2>/dev/null | grep -E "$SUS")
  done; }

. /etc/os-release
echo "Persistence hunt on $HOST ($PRETTY_NAME, $PKG). Report: $P"
HOMES=$(awk -F: '($3==0 || $3>=1000) && $3<65534 {print $6}' /etc/passwd | sort -u)

sec "ACCOUNTS"
awk -F: '$7!~/(nologin|false)$/{print $1,$3,$7}' /etc/passwd >> "$P"
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do flag "extra UID 0 account: $u"; done
awk -F: '$2==""{print $1}' /etc/shadow | while read -r u; do flag "account with EMPTY password: $u"; done
for g in sudo wheel admin; do getent group "$g" >> "$P"; done
grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*#' | while IFS= read -r l; do flag "sudo without password: $l"; done

sec "CRON / AT / TIMERS"
scan /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*
for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [[ -f $f ]] || continue; warn "user crontab: $f"; scan "$f"; done
command -v atq >/dev/null && [[ -n $(atq) ]] && flag "pending at jobs: $(atq | wc -l) (see: at -c <id>)"
systemctl list-timers --all --no-pager >> "$P" 2>/dev/null

sec "SYSTEMD UNITS"
while IFS= read -r f; do
  scan "$f"; owned "$f" || flag "unit not from any package: $f ($(grep -hE '^Exec' "$f" | head -2 | xargs))"
done < <( { find /etc/systemd/system /etc/systemd/user /usr/local/lib/systemd -maxdepth 2 -type f \
             \( -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.socket' \) 2>/dev/null
           find /lib/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f -newermt "$DAYS days ago" 2>/dev/null
           find /etc/systemd/system-generators /usr/local/lib/systemd/system-generators -type f 2>/dev/null; } | sort -u)
for h in $HOMES; do for f in "$h"/.config/systemd/user/*; do [[ -f $f ]] && { flag "per-user systemd unit: $f"; scan "$f"; }; done; done

sec "SHELL STARTUP"
scan /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/environment
for h in $HOMES; do
  scan "$h"/.bashrc "$h"/.profile "$h"/.bash_profile "$h"/.bash_login "$h"/.bash_logout
  grep -hE '^\s*alias\s+(sudo|ls|cd|su|passwd|ssh)=' "$h"/.bashrc "$h"/.bash_aliases 2>/dev/null \
    | grep -vE "alias\s+([a-z]+)='\1( +-[-a-zA-Z=]+)*'\s*$" | while IFS= read -r l; do flag "$h hijacking alias: $l"; done
done

sec "BOOT / LOGIN HOOKS"
scan /etc/rc.local /etc/rc.d/rc.local /etc/update-motd.d/*
find /etc/init.d /etc/rc.d/init.d -type f -newermt "$DAYS days ago" 2>/dev/null | while read -r f; do flag "recently changed init script: $f"; done
grep -rH 'RUN' /etc/udev/rules.d 2>/dev/null | while IFS= read -r l; do flag "udev RUN rule: $l"; done
grep -rHE 'Invoke|Pre-Install-Pkgs' /etc/apt/apt.conf.d 2>/dev/null | grep -E "$SUS" | while IFS= read -r l; do flag "APT hook: $l"; done
for f in /etc/dnf/plugins/*.py /usr/lib/python3*/site-packages/dnf-plugins/*.py; do [[ -f $f ]] && ! owned "$f" && flag "dnf plugin not from a package: $f"; done

sec "PAM / LD_PRELOAD"
grep -rHE 'pam_exec|pam_script' /etc/pam.d 2>/dev/null | while IFS= read -r l; do flag "PAM runs a command: $l"; done
for d in $(readlink -f /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib64/security /usr/lib64/security 2>/dev/null | sort -u); do
  for m in "$d"/*.so; do [[ -f $m ]] && ! owned "$m" && flag "PAM module not from any package: $m"; done
done
[[ -s /etc/ld.so.preload ]] && flag "/etc/ld.so.preload: $(xargs < /etc/ld.so.preload)"
grep -rl 'LD_PRELOAD' /etc/environment /etc/profile.d 2>/dev/null | while read -r f; do flag "LD_PRELOAD set in $f"; done

sec "SSH"
for h in $HOMES; do
  for k in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do
    [[ -s $k ]] || continue; echo "--- $k" >> "$P"; cat "$k" >> "$P"
    grep -qiE "$OOS_RE" <<<"$k" && echo "  $k: OUT OF SCOPE" || warn "$k has $(grep -c . "$k") key(s) - review"
    grep -nE '^(command=|.*,command=)' "$k" | while IFS= read -r l; do flag "forced-command key in $k: $l"; done
  done
  [[ -f $h/.ssh/rc ]] && { flag "$h/.ssh/rc runs on every SSH login"; scan "$h/.ssh/rc"; }
done
[[ -f /etc/ssh/sshrc ]] && { flag "/etc/ssh/sshrc runs on every SSH login"; scan /etc/ssh/sshrc; }
grep -hE '^\s*(AuthorizedKeysFile|AuthorizedKeysCommand|ForceCommand|PermitUserEnvironment|PermitEmptyPasswords\s+yes)' \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | while IFS= read -r l; do flag "sshd: $l"; done

sec "PROCESSES / NETWORK"
for pdir in /proc/[0-9]*; do
  exe=$(readlink "$pdir/exe" 2>/dev/null) || continue
  case "$exe" in *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*)
    flag "PID ${pdir#/proc/} running from $exe : $(tr '\0' ' ' < "$pdir/cmdline" | cut -c1-120)";; esac
done
ss -tulpn >> "$P" 2>/dev/null; ss -tupn state established >> "$P" 2>/dev/null
ss -tlpn 2>/dev/null | grep -E 'users:\(\("(nc|ncat|socat|python[0-9.]*|perl|ruby|php|bash|sh|dash)"' | while IFS= read -r l; do flag "odd listener: $l"; done
find /tmp /dev/shm /var/tmp -xdev -type f \( -perm -u+x -o -name '.*' \) 2>/dev/null | grep -vE '/\.X[0-9]+-lock$' \
  | while read -r f; do flag "executable or hidden file in temp dir: $f"; done

# ---- MariaDB / MySQL (scrutineering) - read-only queries ----
if command -v mysql >/dev/null || command -v mariadb >/dev/null; then
  sec "MARIADB"
  M=$(command -v mariadb || command -v mysql)
  q() { "$M" -NBe "$1" 2>/dev/null; }
  if q 'SELECT 1' >/dev/null; then
    echo "--- users" >> "$P"; q "SELECT user,host,plugin FROM mysql.user" >> "$P"
    q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'" | while read -r l; do warn "DB account allowed from ANY host: $l"; echo "[DB] any-host account: $l" >> "$P"; done
    q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE (password='' OR authentication_string='') AND plugin NOT IN ('unix_socket','auth_socket') AND is_role='N'" 2>/dev/null \
      | while read -r l; do flag "DB account with NO password: $l"; done
    q "SELECT CONCAT(grantee,' ',privilege_type) FROM information_schema.user_privileges WHERE privilege_type IN ('SUPER','FILE','GRANT OPTION','CREATE USER')" \
      | while read -r l; do echo "[DB] powerful privilege: $l" >> "$P"; done
    q "SELECT CONCAT(name,' -> ',dl) FROM mysql.func" | while read -r l; do flag "DB user-defined function (UDF, classic backdoor): $l"; done
    q "SELECT CONCAT(trigger_schema,'.',trigger_name) FROM information_schema.triggers WHERE trigger_schema NOT IN ('mysql','sys','information_schema','performance_schema')" \
      | while read -r l; do warn "DB trigger: $l (review)"; echo "[DB] trigger: $l" >> "$P"; done
    q "SELECT CONCAT(event_schema,'.',event_name,' ',status) FROM information_schema.events" | while read -r l; do flag "DB scheduled event: $l"; done
    q "SHOW VARIABLES WHERE Variable_name IN ('event_scheduler','secure_file_priv','general_log','plugin_dir','local_infile')" >> "$P"
    pd=$(q "SELECT @@plugin_dir")
    for so in "$pd"/*.so; do [[ -f $so ]] && ! owned "$so" && flag "DB plugin not from any package: $so"; done
  else
    warn "Couldn't query MariaDB as root without a password - run: mysql -u root -p < (queries in this script) manually"
  fi
fi

sec "RECENTLY MODIFIED (last $DAYS days)"
timeout 45 find /etc /usr/local /opt /usr/bin /usr/sbin /root /var/spool -xdev -type f -newermt "$DAYS days ago" 2>/dev/null \
  | grep -vE '/(ld.so.cache|mtab|resolv.conf)$' >> "$P"

sec "PACKAGE VERIFY (changed system binaries, up to 2 min)"
if [[ $PKG == deb ]]; then V="dpkg --verify"; else V="rpm -Va --nomtime"; fi
timeout 120 $V 2>/dev/null | awk '$2!="c"' | grep -E '^..5' | tee -a "$P" \
  | grep -E ' /(usr/)?(s)?bin/| /lib(64)?/| /usr/lib(64)?/' | while IFS= read -r l; do flag "modified package file: $l"; done

echo
H=$(grep -c '^\[SUSPICIOUS\]' "$P")
echo "Done: $H suspicious item(s). Full report: $P  (read-only - nothing was changed)"
