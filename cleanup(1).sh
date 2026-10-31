#!/usr/bin/env bash
# cleanup.sh - find persistence and QUARANTINE it (reversible). Debian, Ubuntu, Rocky/RHEL.
#
#   sudo bash cleanup.sh              -> shows the plan, asks once, then fixes everything in it
#   DRY_RUN=1 sudo bash cleanup.sh    -> shows the plan only
#   CONFIRM=0 sudo bash cleanup.sh    -> no question, just do it
#
# Nothing is permanently deleted. Every file is moved to /root/quarantine-<time>/
# (same folder layout), every edited file is backed up first, and an undo script
# is written:  bash /root/quarantine-<time>/restore.sh
# The quarantine folder + actions.log are evidence for the Incident Response Report.
#
# Automatically fixed (high-confidence red-team persistence):
#   fake login shells (e.g. a login game), ForceCommand / command= SSH keys, ~/.ssh/rc,
#   cron/at jobs with reverse-shell/downloader patterns, unpackaged /etc/profile.d files,
#   tampered shell startup files (reset to /etc/skel), hijacking aliases, ld.so.preload,
#   unpackaged udev/motd/generator hooks, systemd units running from temp/hidden paths,
#   processes running from /tmp,/dev/shm or deleted files, executables in temp dirs,
#   extra UID-0 and empty-password accounts (locked, not deleted), NOPASSWD sudo lines.
#
# Reported for you to decide (NOT changed): PAM, MariaDB, modified package binaries,
#   other unpackaged services, SSH keys, scored service configs (rule 10).
# Never touched: whiteteam, dd-agent, ddagentuser, anything datadog (rules 6/14).

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }
DRY_RUN="${DRY_RUN:-0}"; CONFIRM="${CONFIRM:-1}"

TS=$(date +%Y%m%d-%H%M%S)
Q="/root/quarantine-$TS"
LOG="$Q/actions.log"; RESTORE="$Q/restore.sh"
mkdir -p "$Q"; chmod 700 "$Q"
printf '#!/usr/bin/env bash\n# undo cleanup.sh run %s (run as root)\nset -x\n' "$TS" > "$RESTORE"

OOS_RE='whiteteam|dd-agent|ddagentuser|datadog'
SUS='(/dev/(tcp|udp)/|\bnc(at)?\b.*\s-[a-z]*[ec]|bash -i|sh -i|mkfifo|socat|python[0-9.]* -c|perl -e|ruby -e|php -r|base64 (-d|--decode)|(curl|wget)[^|;]*\|\s*(ba)?sh|/tmp/|/dev/shm/|/var/tmp/|chmod ([ugoa]*[+]s|[0-7]?[2467][0-7]{3})|chattr|useradd|usermod|nohup|LD_PRELOAD)'
GAME='hangman|guess|\bread\b +-[a-z]*p'          # login games / prompts in startup files
TOOLS='krak3n|persist|harden|users\.sh|cleanup'  # our own scripts and reports - never quarantined
SELF=$(readlink -f "$0")

. /etc/os-release
if command -v dpkg >/dev/null; then PKG=deb; else PKG=rpm; fi
# Build the list of every package-owned file ONCE (fast lookups instead of one dpkg/rpm call per file)
step_msg() { echo "  ... $*" >&2; }
step_msg "building list of package-owned files (10-30s)"
OWNED_DB="$Q/.owned"
if [[ $PKG == deb ]]; then cat /var/lib/dpkg/info/*.list 2>/dev/null; else rpm -qal 2>/dev/null; fi \
  | sed -E 's#^/usr/#/#' | sort -u > "$OWNED_DB"
owned() { local p r
  for p in "$1" "$(readlink -f "$1")"; do r=${p#/usr}; grep -qxF "$r" "$OWNED_DB" && return 0; done; return 1; }
oos()  { grep -qiE "$OOS_RE" <<<"$*"; }
# calls_unowned FILE -> prints the first absolute path it runs that is an executable no package owns
calls_unowned() { local p
  for p in $(grep -vE '^\s*#' "$1" 2>/dev/null | grep -oE '(^|[[:space:];&|(`"=])/[A-Za-z0-9._/+-]+' | sed -E 's/^[^/]+//' | sort -u); do
    [[ -f $p && -x $p ]] || continue; oos "$p" && continue; grep -qE "$TOOLS" <<<"$p" && continue
    owned "$p" || { echo "$p"; return 0; }
  done; return 1; }
PACKET_ADMINS="${PACKET_ADMINS:-scrutineer techdirector crewchief firecrew}"
warn() { echo -e "\e[1;33m[!] $*\e[0m"; }

# ---------------- collect the plan ----------------
ACTIONS=(); REVIEW=()
add()    { oos "$*" && return; ACTIONS+=("$1"); }        # TYPE|arg|arg|description
review() { oos "$*" && return; REVIEW+=("$*"); }

lines_matching() {  # file regex -> "lineno" for non-comment matching lines
  grep -nE "$2" "$1" 2>/dev/null | grep -vE '^[0-9]+:\s*#' | cut -d: -f1; }

HOMES_USERS=$(awk -F: '($3==0 || ($3>=1000 && $3<65534)) {print $1":"$6":"$7}' /etc/passwd)

step_msg "checking accounts and login shells"
# accounts
while IFS=: read -r u _; do
  [[ $u == root ]] && continue; add "LOCK|$u||extra UID-0 account '$u' -> lock"
done < <(awk -F: '$3==0{print $1":"$3}' /etc/passwd)
for u in $(awk -F: '$2==""{print $1}' /etc/shadow); do add "LOCK|$u||account '$u' has an EMPTY password -> lock"; done

# fake login shells (e.g. a hangman instead of bash)
while IFS=: read -r u h sh; do
  [[ $sh =~ (nologin|false)$ ]] && continue
  grep -qxF "$sh" /etc/shells 2>/dev/null || add "SHELL|$u|$sh|login shell of '$u' is '$sh' (not a real shell) -> /bin/bash"
done <<<"$HOMES_USERS"

step_msg "checking cron and at jobs"
# cron / at
for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [[ -f $f ]] || continue
  for n in $(lines_matching "$f" "$SUS"); do add "CLINE|$f|$n|cron $f line $n: $(sed -n "${n}p" "$f" | cut -c1-90)"; done
done
for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  [[ -f $f ]] && ! owned "$f" && add "QFILE|$f||cron script not from any package: $f"
done
if command -v atq >/dev/null; then
  for j in $(atq | awk '{print $1}'); do add "ATRM|$j||pending at job $j: $(at -c "$j" 2>/dev/null | tail -2 | head -1 | cut -c1-80)"; done
fi

step_msg "checking systemd services"
# systemd
while IFS= read -r f; do
  [[ -f $f ]] || continue; owned "$f" && continue
  ex=$(grep -hE '^\s*Exec' "$f" | head -3 | xargs)
  if grep -qE "$SUS" "$f" || grep -qE '^\s*Exec[A-Za-z]*=-?[@!+]*(/tmp/|/dev/shm/|/var/tmp/|.*/\.[^/]+)' "$f"; then
    add "QUNIT|$f||systemd unit runs from a temp/hidden path or reverse shell: $f ($ex)"
  else review "unpackaged systemd unit (could be a scored service - check before removing): $f ($ex)"; fi
done < <(find /etc/systemd/system /etc/systemd/user /usr/local/lib/systemd /lib/systemd/system /usr/lib/systemd/system \
           -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.socket' \) 2>/dev/null | sort -u)
while IFS=: read -r u h sh; do
  for f in "$h"/.config/systemd/user/*; do [[ -f $f ]] && add "QUNIT|$f|$u|per-user systemd unit for $u: $f"; done
done <<<"$HOMES_USERS"
for f in /etc/systemd/system-generators/* /usr/local/lib/systemd/system-generators/*; do
  [[ -f $f ]] && ! owned "$f" && add "QFILE|$f||systemd generator not from any package: $f"
done

step_msg "checking shell startup files"
# shell startup - system wide
for f in /etc/profile.d/*; do
  [[ -f $f ]] || continue; owned "$f" && continue
  if grep -qE "$SUS|$GAME" "$f"; then add "QFILE|$f||suspicious /etc/profile.d script: $f"
  elif u=$(calls_unowned "$f"); then add "QFILE|$f||/etc/profile.d script runs unpackaged program $u: $f"
  else review "unpackaged /etc/profile.d script (looks harmless): $f"; fi
done
for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/rc.local /etc/rc.d/rc.local; do
  [[ -f $f ]] || continue
  for n in $(lines_matching "$f" "$SUS|$GAME"); do add "CLINE|$f|$n|$f line $n: $(sed -n "${n}p" "$f" | cut -c1-90)"; done
  if u=$(calls_unowned "$f"); then
    for n in $(lines_matching "$f" "$(sed 's/[.[\*^$/]/\\&/g' <<<"$u")"); do add "CLINE|$f|$n|$f line $n runs unpackaged program: $(sed -n "${n}p" "$f" | cut -c1-90)"; done
  fi
done
[[ -s /etc/ld.so.preload ]] && add "QFILE|/etc/ld.so.preload||/etc/ld.so.preload is set: $(xargs < /etc/ld.so.preload)"
for f in /etc/update-motd.d/* /etc/udev/rules.d/*; do
  [[ -f $f ]] || continue; owned "$f" && continue
  if [[ $f == /etc/udev/* ]]; then grep -q 'RUN' "$f" && add "QFILE|$f||udev rule that runs a command: $f"
  elif grep -qE "$SUS|$GAME" "$f" || calls_unowned "$f" >/dev/null; then add "QFILE|$f||suspicious login-message script: $f"
  else review "unpackaged login-message script (looks harmless): $f"; fi
done

# shell startup - per user (reset tampered dotfiles to the clean /etc/skel copy)
while IFS=: read -r u h sh; do
  [[ -d $h && $h != / ]] || continue
  for d in .bashrc .bash_profile .profile .bash_login .bash_logout .zshrc; do
    f="$h/$d"; [[ -f $f ]] || continue
    bad=$(grep -vE '^\s*#' "$f" | grep -cE "$SUS|$GAME|^\s*alias\s+(sudo|su|passwd|ssh|ls|cd)=['\"][^'\"]*[;|&]")
    calls_unowned "$f" >/dev/null && bad=$((bad+1))
    [[ $bad -gt 0 ]] || continue
    if [[ -f /etc/skel/$d ]]; then add "RESETDOT|$f|/etc/skel/$d|$u's $d has $bad suspicious line(s) -> reset to clean /etc/skel copy"
    else for n in $(lines_matching "$f" "$SUS|$GAME"); do add "CLINE|$f|$n|$f line $n: $(sed -n "${n}p" "$f" | cut -c1-90)"; done; fi
  done
  # SSH: forced-command keys and ~/.ssh/rc
  for k in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do
    [[ -s $k ]] || continue
    for n in $(lines_matching "$k" '(^|,)command='); do add "CLINE|$k|$n|SSH key in $k forces a command on login (line $n)"; done
    review "$k has $(grep -cvE '^\s*(#|$)' "$k") key(s) - remove any you don't recognise by hand"
  done
  [[ -f $h/.ssh/rc ]] && add "QFILE|$h/.ssh/rc||$h/.ssh/rc runs on every SSH login"
done <<<"$HOMES_USERS"
[[ -f /etc/ssh/sshrc ]] && add "QFILE|/etc/ssh/sshrc||/etc/ssh/sshrc runs on every SSH login"

step_msg "checking SSH and sudo"
# sshd config (SSH is SCORED on Debian/pitlane -> report only there, rule 10)
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
  [[ -f $f ]] || continue
  for n in $(lines_matching "$f" '^\s*(ForceCommand|AuthorizedKeysCommand|PermitEmptyPasswords\s+yes|PermitUserEnvironment\s+yes)'); do
    l=$(sed -n "${n}p" "$f")
    if [[ $ID == debian ]]; then review "sshd $f line $n: $l  (SSH is scored here - ask White Team before changing)"
    else add "SSHD|$f|$n|sshd $f line $n: $l"; fi
  done
done

# sudo: NOPASSWD lines for specific users (never group lines whiteteam is in, never whiteteam)
wt_groups=$(id -nG whiteteam 2>/dev/null)
for f in /etc/sudoers /etc/sudoers.d/*; do
  [[ -f $f ]] || continue
  for n in $(lines_matching "$f" 'NOPASSWD'); do
    l=$(sed -n "${n}p" "$f"); who=$(awk '{print $1}' <<<"$l")
    if [[ $who == %* ]]; then
      g=${who#%}; [[ " $wt_groups " == *" $g "* ]] && continue   # rule 6: would restrict whiteteam
      review "sudo: group rule '$l' in $f - check who is in group $g"
    elif [[ " $PACKET_ADMINS " == *" $who "* ]]; then review "passwordless sudo for packet admin '$who' in $f (may be original setup)"
    elif [[ $who != root ]]; then add "SUDO|$f|$n|passwordless sudo: '$l' ($f)"; fi
  done
done

step_msg "checking running processes and temp folders"
# processes from temp dirs / deleted files (skip containers: different mount namespace)
mns=$(readlink /proc/$$/ns/mnt)
for pd in /proc/[0-9]*; do
  pid=${pd#/proc/}; [[ $pid == "$$" || $pid == "$PPID" ]] && continue
  exe=$(readlink "$pd/exe" 2>/dev/null) || continue
  [[ $(readlink "$pd/ns/mnt" 2>/dev/null) == "$mns" ]] || continue
  case "$exe" in *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*)
    cmd=$(tr '\0' ' ' < "$pd/cmdline" 2>/dev/null | cut -c1-90)
    grep -qE "$TOOLS" <<<"$exe $cmd" || add "KILL|$pid||process $pid running from $exe : $cmd";; esac
done
# executables / hidden files in temp dirs
while IFS= read -r f; do
  [[ $(readlink -f "$f") == "$SELF" ]] && continue
  grep -qE "$TOOLS" <<<"$f" && continue
  add "QFILE|$f||executable or hidden file in temp dir: $f"
done < <(find /tmp /dev/shm /var/tmp -xdev -type f \( -perm -u+x -o -name '.*' \) 2>/dev/null \
           | grep -vE '/\.X[0-9]+-lock$|/systemd-private-|/snap-private-tmp/|/\.(ICE|X11|font)-unix/')

step_msg "checking PAM and MariaDB"
# report-only areas
grep -rHnE 'pam_exec|pam_script' /etc/pam.d 2>/dev/null | while IFS= read -r l; do echo "PAMEXEC $l"; done > "$Q/.pam"
while IFS= read -r l; do review "PAM runs a command: ${l#PAMEXEC } (edit by hand - a wrong PAM edit can lock everyone out)"; done < "$Q/.pam"; rm -f "$Q/.pam"
if command -v mysql >/dev/null || command -v mariadb >/dev/null; then
  M=$(command -v mariadb || command -v mysql)
  if "$M" -NBe 'SELECT 1' &>/dev/null; then
    while read -r l; do review "MariaDB UDF (backdoor?): $l  -> DROP FUNCTION <name>;"; done < <("$M" -NBe "SELECT CONCAT(name,' -> ',dl) FROM mysql.func" 2>/dev/null)
    while read -r l; do review "MariaDB event: $l  -> ALTER EVENT <db>.<name> DISABLE;"; done < <("$M" -NBe "SELECT CONCAT(event_schema,'.',event_name) FROM information_schema.events" 2>/dev/null)
    while read -r l; do review "MariaDB account: $l (check it's in the original setup; MariaDB is scored - rule 10)"; done < <("$M" -NBe "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ('root','mysql','mariadb.sys','')" 2>/dev/null)
  fi
fi

# de-duplicate (same thing found two ways)
mapfile -t ACTIONS < <(printf '%s\n' "${ACTIONS[@]+"${ACTIONS[@]}"}" | awk 'NF && !s[$0]++')

# ---------------- show the plan ----------------
echo
echo "cleanup.sh on $(hostname -s) ($PRETTY_NAME)"
echo "==================== WILL FIX (${#ACTIONS[@]}) ===================="
i=0; for a in "${ACTIONS[@]+"${ACTIONS[@]}"}"; do i=$((i+1)); printf "%3d. %s\n" "$i" "${a##*|}"; done
[[ ${#ACTIONS[@]} -eq 0 ]] && echo "  nothing high-confidence found"
echo "==================== REVIEW BY HAND, NOT CHANGED (${#REVIEW[@]}) ===================="
for r in "${REVIEW[@]+"${REVIEW[@]}"}"; do echo "  - $r"; done
{ echo "PLAN"; printf '%s\n' "${ACTIONS[@]+"${ACTIONS[@]}"}"; echo "REVIEW"; printf '%s\n' "${REVIEW[@]+"${REVIEW[@]}"}"; } > "$Q/plan.txt"

if [[ $DRY_RUN == 1 || ${#ACTIONS[@]} -eq 0 ]]; then echo; echo "No changes made. Plan saved: $Q/plan.txt"; exit 0; fi

MODE=all
if [[ $CONFIRM == 1 ]]; then
  printf "\nApply? [y] fix all %d / [r] review one by one / [n] cancel: " "${#ACTIONS[@]}"
  read -r ans </dev/tty || ans=n
  case "${ans,,}" in y|yes) MODE=all ;; r) MODE=review ;; *) echo "Cancelled - nothing changed."; exit 0 ;; esac
fi

# ---------------- apply ----------------
backup() {   # copy a file into the quarantine once, add restore line
  local f=$1; [[ -e $Q/backup$f ]] && return
  mkdir -p "$Q/backup$(dirname "$f")"; cp -a "$f" "$Q/backup$f"
  echo "cp -a '$Q/backup$f' '$f'" >> "$RESTORE"; }
quarantine() {
  local f=$1; mkdir -p "$Q/files$(dirname "$f")"
  if mv "$f" "$Q/files$f" 2>/dev/null; then echo "mkdir -p '$(dirname "$f")'; mv '$Q/files$f' '$f'" >> "$RESTORE"; return 0; fi
  chattr -i -a "$f" 2>/dev/null; mv "$f" "$Q/files$f" && echo "mv '$Q/files$f' '$f'" >> "$RESTORE"; }
log() { echo "$*"; echo "$(date +%T) $*" >> "$LOG"; }
# End only this account's own login sessions. NEVER "pkill -u" a UID-0 account or a UID
# shared with another account: that would kill every root process (sshd, MariaDB, ...).
kill_sessions() { local u=$1 uid t
  uid=$(id -u "$u" 2>/dev/null) || return 0
  if [[ $uid == 0 || $(awk -F: -v i="$uid" '$3==i' /etc/passwd | wc -l) -gt 1 ]]; then
    for t in $(who | awk -v u="$u" '$1==u{print $2}'); do pkill -KILL -t "$t" 2>/dev/null; done
  else pkill -KILL -u "$u" 2>/dev/null; fi; return 0; }

SSHD_CHANGED=0; CRON_CHANGED=0
for a in "${ACTIONS[@]}"; do
  IFS='|' read -r t x y desc <<<"$a"
  if [[ $MODE == review ]]; then
    printf "\n%s\n  fix this? [y/N/q]: " "$desc"; read -r ans </dev/tty || ans=q
    [[ ${ans,,} == q ]] && break; [[ ${ans,,} == y ]] || { log "SKIPPED: $desc"; continue; }
  fi
  case $t in
    LOCK)   usermod -L "$x" && usermod -e 1 "$x" && kill_sessions "$x"
            echo "usermod -U -e '' '$x'" >> "$RESTORE"; log "LOCKED: $desc" ;;
    SHELL)  echo "usermod -s '$y' '$x'" >> "$RESTORE"
            [[ -f $y ]] && ! owned "$y" && quarantine "$y"
            usermod -s /bin/bash "$x" && log "FIXED: $desc" ;;
    CLINE)  backup "$x"; chattr -i -a "$x" 2>/dev/null
            sed -i "${y}s/^/#QUARANTINED-$TS# /" "$x" && log "COMMENTED OUT: $desc"
            [[ $x == /var/spool/cron/* ]] && CRON_CHANGED=1 ;;
    QFILE)  quarantine "$x" && log "QUARANTINED: $desc" ;;
    QUNIT)  n=$(basename "$x")
            if [[ -n $y ]]; then runuser -u "$y" -- systemctl --user disable --now "$n" &>/dev/null
            else systemctl disable --now "$n" &>/dev/null; fi
            quarantine "$x" && systemctl daemon-reload && log "STOPPED + QUARANTINED: $desc"
            echo "systemctl daemon-reload  # then re-enable $n if needed" >> "$RESTORE" ;;
    RESETDOT) backup "$x"; chattr -i -a "$x" 2>/dev/null
            o=$(stat -c '%U:%G' "$x"); cp "$y" "$x" && chown "$o" "$x" && log "RESET: $desc" ;;
    ATRM)   at -c "$x" > "$Q/at-job-$x.txt" 2>/dev/null; atrm "$x" && log "REMOVED (saved to at-job-$x.txt): $desc" ;;
    KILL)   cp "/proc/$x/exe" "$Q/killed-pid$x.bin" 2>/dev/null
            tr '\0' ' ' < "/proc/$x/cmdline" > "$Q/killed-pid$x.cmdline" 2>/dev/null
            kill -9 "$x" 2>/dev/null && log "KILLED (binary saved to killed-pid$x.bin): $desc" ;;
    SSHD)   backup "$x"; sed -i "${y}s/^/#QUARANTINED-$TS# /" "$x" && SSHD_CHANGED=1 && log "COMMENTED OUT: $desc" ;;
    SUDO)   backup "$x"; sed -i "${y}s/^/#QUARANTINED-$TS# /" "$x"
            if visudo -c &>/dev/null; then log "COMMENTED OUT: $desc"
            else cp -a "$Q/backup$x" "$x"; warn "sudoers check failed - put $x back, not changed"; fi ;;
  esac
done

if [[ $SSHD_CHANGED == 1 ]]; then
  if sshd -t 2>>"$LOG"; then systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; log "sshd reloaded"
  else warn "sshd config test FAILED - restoring sshd files"
       for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do [[ -f $Q/backup$f ]] && cp -a "$Q/backup$f" "$f"; done; fi
fi
[[ $CRON_CHANGED == 1 ]] && touch /var/spool/cron/crontabs /var/spool/cron 2>/dev/null

echo
echo "Done. Everything removed is in $Q (evidence for the IR report)."
echo "Log:  $LOG"
echo "Undo: bash $RESTORE"
echo "Then check the Hermes dashboard - every scored service should still be green."
