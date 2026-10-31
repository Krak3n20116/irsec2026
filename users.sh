#!/usr/bin/env bash
# users.sh - change passwords, lock, or delete local users, one at a time.
# Run as root:  sudo ./users.sh            (DRY_RUN=1 sudo ./users.sh = change nothing)
#
# For each user who can log in you choose:
#   c = change password (you type it)      g = generate a random password
#   l = lock the account (reversible)      x = DELETE the user and their files
#   s = skip                               q = quit
#
# IRSeC 2026 safety rails:
#   - whiteteam, dd-agent, ddagentuser are never shown or touched (rules 6 / 14)
#   - root and system accounts (UID < 1000) are never touched
#   - users listed in the Blue Team Packet need the username typed to delete
#     (scoring checks may log in as them)
#   - before deleting, the home folder, crontab, account lines and any other
#     files the user owns are archived to /root/usertool-<time>/ (evidence for
#     the Incident Response Report, and a way back if it was a mistake)
#   - passwords are never written to the log

set -uo pipefail

PROTECTED_USERS="${PROTECTED_USERS:-whiteteam dd-agent ddagentuser}"
PACKET_USERS="${PACKET_USERS:-scrutineer techdirector crewchief firecrew jackcrew garagecrew celebrity pitlaner reserve gunners}"
DRY_RUN="${DRY_RUN:-0}"

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 1; }
: </dev/tty 2>/dev/null || { echo "Needs a terminal to ask questions."; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
OUT="/root/usertool-$TS"
mkdir -p "$OUT"; chmod 700 "$OUT"
LOG="$OUT/actions.log"

say()  { echo "$*" | tee -a "$LOG"; }
warn() { echo -e "\e[1;33m[!] $*\e[0m"; echo "[!] $*" >> "$LOG"; }
ask()  { local a; printf "%s" "$1" >/dev/tty; read -r a </dev/tty || a=q; echo "$a"; }
in_list() { local w; for w in $2; do [[ $w == "$1" ]] && return 0; done; return 1; }
genpw() { tr -dc 'A-Za-z0-9@#%+=' </dev/urandom 2>/dev/null | head -c 16; }

delete_user() {
  local u=$1 home bk n
  home=$(getent passwd "$u" | cut -d: -f6)
  bk="$OUT/deleted-$u"

  echo
  echo "About to DELETE '$u'. This will:"
  echo "  - stop every process running as $u"
  echo "  - remove their crontab and the account itself"
  echo "  - delete their home folder ($home) and mail"
  echo "  Everything is archived first to $bk/"

  if in_list "$u" "$PACKET_USERS"; then
    warn "'$u' is a user listed in the Blue Team Packet. A scored check may log in as it."
    [[ $(ask "  Type the username '$u' to confirm deleting it: ") == "$u" ]] || { say "Not deleted: $u (confirmation didn't match)"; return; }
  else
    [[ $(ask "  Delete '$u'? [y/N]: ") =~ ^[yY] ]] || { say "Not deleted: $u"; return; }
  fi

  if [[ $DRY_RUN == 1 ]]; then say "[dry-run] would archive and delete $u"; return; fi

  # ---- archive (evidence + rollback) ----
  mkdir -p "$bk"
  getent passwd "$u" > "$bk/passwd.line"
  getent shadow "$u" > "$bk/shadow.line"; chmod 600 "$bk/shadow.line"
  id "$u" > "$bk/groups.txt" 2>&1
  crontab -l -u "$u" > "$bk/crontab.txt" 2>/dev/null
  ps -u "$u" -o pid,ppid,etime,cmd > "$bk/processes.txt" 2>/dev/null
  grep -rlw -- "$u" /etc/sudoers /etc/sudoers.d 2>/dev/null > "$bk/sudoers-mentions.txt"
  [[ -d $home && $home != / ]] && tar czf "$bk/home.tgz" -C / "${home#/}" 2>/dev/null \
    && say "archived $home -> $bk/home.tgz"

  # files the user owns OUTSIDE their home (could be a backdoor - or something a service needs)
  timeout 60 find / -xdev -user "$u" -not -path "$home/*" -not -path "$home" \
    -not -path '/proc/*' -not -path '/var/mail/*' -not -path '/var/spool/mail/*' 2>/dev/null > "$bk/other-files.txt"
  n=$(grep -c . "$bk/other-files.txt")

  # ---- delete ----
  pkill -KILL -u "$u" 2>/dev/null; sleep 1
  crontab -r -u "$u" 2>/dev/null
  if userdel -r "$u" 2>>"$LOG"; then
    say "DELETED user $u and home folder"
  else
    warn "userdel failed for $u - see $LOG"; return
  fi

  if [[ -s $bk/sudoers-mentions.txt ]]; then
    warn "$u is still named in: $(xargs < "$bk/sudoers-mentions.txt") - review those sudo rules by hand (use visudo)"
  fi

  if [[ $n -gt 0 ]]; then
    echo "  $u also owned $n file(s)/folder(s) outside the home folder:"
    head -15 "$bk/other-files.txt" | sed 's/^/    /'
    [[ $n -gt 15 ]] && echo "    ... full list in $bk/other-files.txt"
    if [[ $(ask "  Archive and delete these too? Only say yes if none belong to a service [y/N]: ") =~ ^[yY] ]]; then
      tar czf "$bk/other-files.tgz" --no-recursion -T "$bk/other-files.txt" 2>/dev/null
      # files first, then now-empty folders (deepest first); never remove a non-empty folder
      grep -v '^$' "$bk/other-files.txt" | while IFS= read -r f; do [[ -d $f ]] || rm -f -- "$f"; done
      sort -r "$bk/other-files.txt" | while IFS= read -r f; do [[ -d $f ]] && rmdir -- "$f" 2>/dev/null; done
      say "deleted $u's other files (archive: $bk/other-files.tgz)"
    else
      say "kept $u's other files (list: $bk/other-files.txt) - they now show as owned by a number"
    fi
  fi
}

# ---------------- main ----------------
USERS=""
for u in $(awk -F: '$3>=1000 && $3<65534 && $7!~/(nologin|false)$/{print $1}' /etc/passwd); do
  in_list "$u" "$PROTECTED_USERS" || USERS+="$u "
done

echo "Users who can log in (whiteteam / Datadog accounts hidden - never touched):"
for u in $USERS; do
  tag=""; in_list "$u" "$PACKET_USERS" && tag="  (in packet)" || tag="  (NOT in packet - check this one)"
  id -nG "$u" | grep -qwE 'sudo|admin|wheel' && tag+="  [admin]"
  printf "  %-16s%s\n" "$u" "$tag"
done
[[ -z $USERS ]] && { echo "  none"; exit 0; }
[[ $DRY_RUN == 1 ]] && echo "DRY RUN: nothing will be changed."
echo "Log (no passwords): $LOG"

for u in $USERS; do
  while true; do
    a=$(ask $'\n'"User '$u': [c]hange / [g]enerate / [l]ock / [x] delete / [s]kip / [q]uit: ")
    case "${a,,}" in
      c)
        if [[ $DRY_RUN == 1 ]]; then say "[dry-run] would change password for $u"; break; fi
        if passwd "$u" </dev/tty >/dev/tty 2>&1; then say "Password changed for $u"; break
        else echo "passwd failed - try again or pick another option" >/dev/tty; fi ;;
      g)
        if [[ $DRY_RUN == 1 ]]; then say "[dry-run] would set a generated password for $u"; break; fi
        p=$(genpw)
        if echo "$u:$p" | chpasswd; then
          say "Password changed for $u (generated)"
          printf "  >>> %s : %s   <- write this down now, it is NOT saved anywhere\n" "$u" "$p" >/dev/tty
          ask "  Press Enter once you've recorded it... " >/dev/null
          clear >/dev/tty 2>/dev/null || printf '\n%.0s' {1..40} >/dev/tty
        else warn "chpasswd failed for $u"; fi
        unset p; break ;;
      l)
        if [[ $DRY_RUN == 1 ]]; then say "[dry-run] would lock $u"; break; fi
        usermod -L "$u" && usermod -e 1 "$u" && pkill -KILL -u "$u" 2>/dev/null
        say "Locked $u (undo: usermod -U -e '' $u)"; break ;;
      x) delete_user "$u"; break ;;
      s) say "Skipped $u"; break ;;
      q) say "Stopped."; break 2 ;;
      *) echo "Please type c, g, l, x, s or q." >/dev/tty ;;
    esac
  done
done

echo
echo "Done. Log: $LOG"
ls -d "$OUT"/deleted-* 2>/dev/null | sed 's/^/Archive: /'
echo "Restore a deleted home:  tar xzf $OUT/deleted-<user>/home.tgz -C /  (recreate the user first)"
