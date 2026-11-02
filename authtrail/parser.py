"""Parse Linux authentication logs (auth.log / secure) into structured events.

Two timestamp formats are supported:

  BSD syslog   Nov  2 03:14:07 db01 sshd[4242]: Accepted password for admin from ...
  RFC 3339     2026-11-02T03:14:07.123456+00:00 db01 sshd[4242]: Accepted password ...

BSD timestamps carry no year and no time zone. The year is inferred (see
`_infer_years`), and the time is taken as the server's local time. RFC 3339
timestamps with an offset are converted to UTC.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

BSD_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
                    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
ISO_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
                    r"(?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")

# rsyslog collapses identical lines: "message repeated 5 times: [ Failed password for ...]".
# Each repeat is a real attempt, so the event is expanded N times instead of counted once.
REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<msg>.*)\]$")
MAX_REPEAT = 10_000
PROVISIONAL_YEAR = 2028     # a leap year, so "Feb 29" parses before the real year is known

# OpenSSH 9.8 moved per-connection logging into a separate "sshd-session" binary.
SSHD = {"sshd", "sshd-session"}

# Usernames are attacker-controlled and may contain spaces, so these patterns are
# anchored at the END of the line ($). An attacker can type a fake
# "from <ip> port <n>" as a username, but only the address sshd wrote last can be
# followed by end-of-line, so the fake one always ends up inside the user group.
# See tests: LogInjectionTests.
SSH_FAIL_RE = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) "
                         r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?: \[preauth\])?$")
SSH_ACCEPT_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*) "
                           r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?:: (?P<key>.*))?$")
SSH_INVALID_RE = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")
SSH_SESSION_RE = re.compile(r"^pam_unix\(sshd(?:-session)?:session\): session (?P<state>opened|closed) "
                            r"for user (?P<user>[^\s(]+)")

SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
SU_OK_RE = re.compile(r"^(?:Successful su for (?P<target0>\S+) by (?P<user0>\S+)|"
                      r"\(to (?P<target>\S+)\) (?P<user>\S+) on \S+)$")
SU_FAIL_RE = re.compile(r"^FAILED (?:su|SU) (?:for (?P<target>\S+) by (?P<user>\S+)|"
                        r"\(to (?P<target2>\S+)\) (?P<user2>\S+) on \S+)")
USERADD_RE = re.compile(r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
                        r"home=(?P<home>[^,]+), shell=(?P<shell>[^,]+)")
GROUP_ADD_RE = re.compile(r"^add '(?P<name>[^']+)' to (?P<shadow>shadow )?group '(?P<group>[^']+)'")
GPASSWD_RE = re.compile(r"^user (?P<name>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")
PASSWD_RE = re.compile(r"pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<name>\S+)")
USERDEL_RE = re.compile(r"^delete user '(?P<name>[^']+)'")


@dataclass
class Event:
    ts: datetime
    host: str
    prog: str
    pid: int | None
    kind: str
    source: str
    lineno: int
    raw: str
    user: str = ""
    ip: str = ""
    port: int | None = None
    method: str = ""
    invalid: bool = False
    detail: dict = field(default_factory=dict)


@dataclass
class ParseResult:
    events: list
    source: str = ""
    lines: int = 0
    recognized: int = 0     # lines in a known syslog format
    unparsed: list = field(default_factory=list)   # line numbers in no known format


def normalize_ip(text):
    """Return a canonical IP string, or "" if the text is not an IP address."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def classify(prog, msg):
    """Turn one syslog message into (kind, fields), or None if it isn't security-relevant."""
    if prog in SSHD:
        if m := SSH_FAIL_RE.match(msg):
            return "ssh_fail", {"user": m["user"], "ip": m["ip"], "port": int(m["port"]),
                                "method": m["method"], "invalid": bool(m["invalid"])}
        if m := SSH_ACCEPT_RE.match(msg):
            return "ssh_accept", {"user": m["user"], "ip": m["ip"], "port": int(m["port"]),
                                  "method": m["method"], "detail": {"key": m["key"] or ""}}
        if m := SSH_INVALID_RE.match(msg):
            return "ssh_invalid_user", {"user": m["user"], "ip": m["ip"],
                                        "port": int(m["port"]) if m["port"] else None,
                                        "invalid": True}
        if m := SSH_SESSION_RE.match(msg):
            kind = "ssh_session_open" if m["state"] == "opened" else "ssh_session_close"
            return kind, {"user": m["user"]}
        return None

    if prog == "sudo":
        return _classify_sudo(msg)

    if prog == "su":
        if m := SU_FAIL_RE.match(msg):
            return "su_fail", {"user": m["user"] or m["user2"] or "",
                               "detail": {"target": m["target"] or m["target2"] or ""}}
        if m := SU_OK_RE.match(msg):
            return "su_ok", {"user": m["user"] or m["user0"],
                             "detail": {"target": m["target"] or m["target0"]}}
        return None

    if prog == "useradd" and (m := USERADD_RE.match(msg)):
        return "user_add", {"detail": {"name": m["name"], "uid": int(m["uid"]), "gid": int(m["gid"]),
                                       "home": m["home"], "shell": m["shell"]}}
    if prog in ("useradd", "usermod") and (m := GROUP_ADD_RE.match(msg)):
        if m["shadow"]:
            return None     # the same change is also logged for /etc/gshadow; count it once
        return "group_add", {"detail": {"name": m["name"], "group": m["group"]}}
    if prog == "gpasswd" and (m := GPASSWD_RE.match(msg)):
        return "group_add", {"user": m["by"], "detail": {"name": m["name"], "group": m["group"]}}
    if prog in ("passwd", "chpasswd") and (m := PASSWD_RE.search(msg)):
        return "password_change", {"detail": {"name": m["name"]}}
    if prog == "userdel" and (m := USERDEL_RE.match(msg)):
        return "user_delete", {"detail": {"name": m["name"]}}
    return None


def _classify_sudo(msg):
    """sudo: "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/id".

    COMMAND is always last and may itself contain " ; ", so it is cut off before the
    remaining fields are split. Fields without "=" are the reason for a refusal,
    such as "user NOT in sudoers" or "3 incorrect password attempts".
    """
    m = SUDO_RE.match(msg)
    if not m or "pam_unix" in msg:
        return None
    rest, _, command = m["rest"].partition("COMMAND=")
    fields, reasons = {}, []
    for part in rest.split(" ; "):
        part = part.strip(" ;")
        if not part:
            continue
        key, eq, value = part.partition("=")
        if eq and key.isupper():
            fields[key] = value
        else:
            reasons.append(part)
    detail = {"command": command.strip(), "runas": fields.get("USER", "root"),
              "tty": fields.get("TTY", ""), "pwd": fields.get("PWD", "")}
    reason = " ; ".join(reasons)
    if not reason:
        return "sudo_cmd", {"user": m["user"], "detail": detail}
    detail["reason"] = reason
    if "incorrect password" in reason:
        attempts = re.match(r"(\d+)", reason)
        detail["attempts"] = int(attempts[1]) if attempts else 1
        return "sudo_badpass", {"user": m["user"], "detail": detail}
    if "NOT in sudoers" in reason or "not allowed" in reason:
        return "sudo_denied", {"user": m["user"], "detail": detail}
    return None


def parse_text(text, source="<input>", year=None, now=None):
    """Parse a whole log file. `year` pins the year for BSD timestamps; otherwise it is inferred."""
    now = now or datetime.now()
    text = text.removeprefix("﻿")      # a BOM would break the first line's timestamp
    result = ParseResult(events=[], source=source)
    bsd = []                                 # (event index, month) for year inference
    for lineno, line in enumerate(text.splitlines(), 1):
        result.lines += 1
        if not line.strip():
            continue
        parsed = _parse_line(line)
        if parsed is None:
            result.unparsed.append(lineno)
            continue
        result.recognized += 1
        ts, host, prog, pid, msg, month = parsed
        count = 1
        if r := REPEAT_RE.match(msg):
            msg, count = r["msg"].strip(), min(int(r["n"]), MAX_REPEAT)
        classified = classify(prog, msg)
        if classified is None:
            continue
        kind, fields = classified
        if "ip" in fields:
            fields["ip"] = normalize_ip(fields["ip"])
            if not fields["ip"]:
                continue     # not an address: malformed or tampered line
        for _ in range(count):
            if month:
                bsd.append((len(result.events), month))
            result.events.append(Event(ts=ts, host=host, prog=prog, pid=pid, kind=kind,
                                       source=source, lineno=lineno, raw=line, **fields))
    if bsd:
        _infer_years(result.events, bsd, year, now)
    return result


def _parse_line(line):
    if m := BSD_RE.match(line):
        month = MONTHS.get(m["mon"])
        try:
            hh, mm, ss = map(int, m["time"].split(":"))
            ts = datetime(PROVISIONAL_YEAR, month, int(m["day"]), hh, mm, ss)
        except (TypeError, ValueError):
            return None
        return ts, m["host"], m["prog"], _pid(m), m["msg"], month
    if m := ISO_RE.match(line):
        try:
            ts = datetime.fromisoformat(m["ts"])
        except ValueError:
            return None
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts, m["host"], m["prog"], _pid(m), m["msg"], 0
    return None


def _pid(m):
    return int(m["pid"]) if m["pid"] else None


def _infer_years(events, bsd, year, now):
    """Assign years to BSD timestamps, which don't record one.

    Walking the file in order, a month that jumps backwards by six or more
    (Dec -> Jan) means the year rolled over. With a given year, that is the
    year of the first line. Without one, the file is anchored so its last line
    falls in the most recent year that isn't in the future: December logs read
    in January land in last year, not next year.
    """
    offset, prev, offsets = 0, None, []
    for _, month in bsd:
        if prev is not None and prev - month >= 6:
            offset += 1
        prev = month
        offsets.append(offset)
    if year is not None:
        base = year
    else:
        base = now.year - offsets[-1]
        if _with_year(events[bsd[-1][0]].ts, now.year) > now + timedelta(days=1):
            base -= 1
    for (idx, _), off in zip(bsd, offsets):
        events[idx].ts = _with_year(events[idx].ts, base + off)


def _with_year(ts, year):
    try:
        return ts.replace(year=year)
    except ValueError:          # Feb 29 in a non-leap year
        return ts.replace(year=year, day=28)
