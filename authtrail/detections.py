"""Stateful detections over parsed auth events, correlated into incidents.

Detection happens in three passes:

1. Attack detection: sliding windows over failed logins find brute force (one
   source, many tries), password spraying (one source, many accounts, few tries
   each) and distributed attacks (many sources, one account).
2. Compromise detection: a successful login from a source that was just failing
   opens an *incident* that lasts until that SSH session closes.
3. Host activity: account changes, privileged groups and risky sudo commands.
   Anything that happens inside an incident's window is raised one severity
   level and attached to the incident, because the same command means more
   when it follows a break-in.
"""

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
VERDICTS = {"critical": "COMPROMISE LIKELY", "high": "HIGH RISK", "medium": "SUSPICIOUS"}
CLEAN = "NO THREATS FOUND"

MITRE = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1136.001": "Create Account: Local Account",
    "T1098": "Account Manipulation",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1531": "Account Access Removal",
    "T1548.001": "Abuse Elevation Control Mechanism: Setuid and Setgid",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1070.002": "Indicator Removal: Clear Linux or Mac System Logs",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
}

PASSWORD_METHODS = {"password", "keyboard-interactive", "keyboard-interactive/pam"}
# Membership in docker or lxd is root-equivalent: either can mount the host's filesystem.
PRIV_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "lxd"}

# Explicit list rather than ipaddress.is_private, which also counts the RFC 5737
# documentation ranges (used by the samples) as private.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]

URL_RE = re.compile(r"https?://[^\s'\"|;<>]+")

# Risky sudo commands, most severe first; the first match wins.
# (pattern, severity, title, ATT&CK, summary clause)
SUSPICIOUS_COMMANDS = [(re.compile(p, re.I), *rest) for p, *rest in [
    (r"\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|da|z)?sh\b",
     "high", "Download piped into a shell", ["T1105", "T1059.004"], "piped a download into a shell"),
    (r"/dev/tcp/|\bnc(?:at)?\b[^|;]*\s-[a-z]*[ec]\b|\bsocat\b.*\bexec:",
     "high", "Reverse shell command", ["T1059.004"], "ran a reverse-shell command"),
    (r"\b(?:rm|shred|truncate|unlink)\b[^;|]*(?:/var/log/|\.bash_history|wtmp|btmp|lastlog)"
     r"|>\s*(?:/var/log/|\S*\.bash_history)|\bhistory\s+-c\b|\bunset\s+HISTFILE\b"
     r"|\bjournalctl\b.*--vacuum|/dev/null\s+\S*\.bash_history",
     "high", "Logs or shell history wiped", ["T1070.002", "T1070.003"], "wiped logs"),
    (r"\bufw\s+disable\b|\biptables\s+(?:-F|--flush|-P\s+INPUT\s+ACCEPT)|\bnft\s+flush\s+ruleset"
     r"|\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|nftables)\b",
     "high", "Host firewall disabled", ["T1562.004"], "disabled the firewall"),
    (r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:auditd|apparmor|falcon-sensor|wazuh-agent|osqueryd)\b"
     r"|\bsetenforce\s+0\b|\bauditctl\s+-D\b",
     "high", "Security tooling disabled", ["T1562.001"], "disabled security tooling"),
    (r"\bchmod\b[^;|]*(?:\b[ugoa]*\+[rwx]*s|\s[2467][0-7]{3}\b)",
     "medium", "Setuid or setgid bit set", ["T1548.001"], "set a setuid bit"),
    (r"/etc/g?shadow\b|\bunshadow\b",
     "medium", "Password hash file accessed", ["T1003.008"], "accessed the password hash file"),
    (r"authorized_keys",
     "medium", "SSH authorized_keys accessed", ["T1098.004"], "planted an SSH key"),
    (r"\bcrontab\b|/etc/cron|/var/spool/cron",
     "medium", "Cron job changed", ["T1053.003"], "changed a cron job"),
    (r"/etc/sudoers|\bvisudo\b",
     "medium", "sudoers accessed", ["T1548.003"], "edited sudoers"),
    (r"\bsystemctl\s+enable\b|/etc/systemd/system/",
     "low", "Service enabled or created", ["T1543.002"], "enabled a service"),
    (r"^(?:/usr)?/bin/(?:ba|da|z)?sh$|^(?:/usr)?/bin/su(?:\s|$)",
     "low", "Interactive root shell", ["T1548.003"], "opened a root shell"),
]]


@dataclass
class Thresholds:
    brute_failures: int = 10                       # failures from one source...
    brute_window: timedelta = timedelta(minutes=10)    # ...inside this window
    spray_users: int = 8                           # distinct accounts from one source...
    spray_window: timedelta = timedelta(minutes=30)
    spray_max_per_user: float = 3.0                # ...with at most this many tries each
    distributed_ips: int = 5                       # distinct sources against one account...
    distributed_window: timedelta = timedelta(hours=1)
    compromise_failures: int = 5                   # failures before a success that make it suspect
    compromise_lookback: timedelta = timedelta(hours=6)
    session_window: timedelta = timedelta(hours=12)    # incident length if the session never closes
    sudo_failures: int = 3
    su_failures: int = 3


@dataclass
class Finding:
    severity: str
    rule: str
    title: str
    detail: str
    mitre: list
    ts: datetime
    end: datetime | None = None
    host: str = ""
    ip: str = ""
    user: str = ""
    actor: str | None = None     # who acted, for incident correlation; None = not logged
    evidence: list = field(default_factory=list)    # [(source, lineno)]
    why: str = ""                # short clause for the plain-English summary
    incident: int | None = None
    base_severity: str = ""      # severity before incident escalation


@dataclass
class Incident:
    id: int
    host: str
    ip: str
    user: str
    start: datetime
    end: datetime
    session_closed: bool
    trigger: Finding
    findings: list = field(default_factory=list)


@dataclass
class Attacker:
    ip: str
    internal: bool
    failures: int
    users: Counter
    first: datetime
    last: datetime
    hosts: set
    label: str = "low volume"
    successes: list = field(default_factory=list)


@dataclass
class Analysis:
    sources: list
    hosts: list
    stats: dict
    first: datetime | None
    last: datetime | None
    findings: list
    incidents: list
    attackers: list
    iocs: dict
    verdict: str
    summary: str
    failures_timeline: list      # timestamps of every failed attempt, for the activity chart


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def _evidence(events, limit=8):
    """(file, line) references, once each: an expanded "message repeated" line is one line."""
    return list(dict.fromkeys((e.source, e.lineno) for e in events))[:limit]


def _fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _span(start, end):
    minutes = (end - start).total_seconds() / 60
    if minutes < 1:
        return "under a minute"
    if minutes < 90:
        return f"{minutes:.0f} min"
    return f"{minutes / 60:.1f} h"


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _verb(n):
    return "needs" if n == 1 else "need"


# --------------------------------------------------------------------------- windows

def peak_window(events, window):
    """Largest number of events inside any sliding window of the given length. O(n)."""
    best, lo, hi, left = 0, 0, -1, 0
    for right, ev in enumerate(events):
        while ev.ts - events[left].ts > window:
            left += 1
        if right - left + 1 > best:
            best, lo, hi = right - left + 1, left, right
    return best, events[lo:hi + 1]


def peak_distinct(events, window, key):
    """Largest number of distinct key(event) values inside any sliding window. O(n)."""
    counts, best, lo, hi, left = Counter(), 0, 0, -1, 0
    for right, ev in enumerate(events):
        counts[key(ev)] += 1
        while ev.ts - events[left].ts > window:
            k = key(events[left])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            left += 1
        if len(counts) > best:
            best, lo, hi = len(counts), left, right
    return best, events[lo:hi + 1]


def failed_attempts(events):
    """One event per failed login attempt.

    sshd writes "Invalid user X" when the connection starts and then one
    "Failed password for invalid user X" per password tried, so counting both
    would double the total. The Invalid line only counts when its connection
    (same host and sshd PID) produced no Failed line: a key-only server rejects
    unknown users before any password is tried.
    """
    failed_pids = {(e.host, e.pid) for e in events if e.kind == "ssh_fail" and e.pid}
    return [e for e in events if e.kind == "ssh_fail" or
            (e.kind == "ssh_invalid_user" and (e.pid is None or (e.host, e.pid) not in failed_pids))]


# --------------------------------------------------------------------------- pass 1: attacks

def detect_attacks(attempts, th):
    findings, attackers, labels = [], {}, {}
    by_ip, by_user = defaultdict(list), defaultdict(list)
    for e in attempts:
        by_ip[e.ip].append(e)
        by_user[e.user].append(e)

    for ip, evs in by_ip.items():
        attackers[ip] = Attacker(ip=ip, internal=is_internal(ip), failures=len(evs),
                                 users=Counter(e.user for e in evs), first=evs[0].ts,
                                 last=evs[-1].ts, hosts={e.host for e in evs})
        n_users, spray = peak_distinct(evs, th.spray_window, key=lambda e: e.user)
        n_burst, burst = peak_window(evs, th.brute_window)
        where = f" ({'internal' if attackers[ip].internal else 'external'} address)"
        if n_users >= th.spray_users and len(spray) / n_users <= th.spray_max_per_user:
            invalid = sum(1 for e in spray if e.invalid)
            guessed = any(e.kind == "ssh_fail" for e in spray)
            labels[ip] = attackers[ip].label = "password spray" if guessed else "username probe"
            if guessed:
                title, how = (f"Password spraying from {ip}",
                              "Spraying tries a few common passwords across many accounts to stay "
                              "under per-account lockout limits.")
            else:
                title, how = (f"Username probing from {ip}",
                              "No password was ever tried: the server only accepts keys, so this "
                              "source is enumerating account names, often ahead of a later attack.")
            findings.append(Finding(
                "medium", "ssh.spray", title,
                f"{_plural(n_users, 'account')} tried in {_span(spray[0].ts, spray[-1].ts)} with "
                f"{_plural(len(spray), 'attempt')} in total{where}. {how} "
                f"{invalid} of the attempts named accounts that don't exist.",
                ["T1110.003"], spray[0].ts, spray[-1].ts, spray[0].host, ip,
                evidence=_evidence(spray),
                why=f"{ip} sprayed {_plural(n_users, 'account')}"))
        elif n_burst >= th.brute_failures:
            labels[ip] = attackers[ip].label = "brute force"
            top = Counter(e.user for e in burst).most_common(3)
            findings.append(Finding(
                "medium", "ssh.bruteforce", f"SSH brute force from {ip}",
                f"{_plural(n_burst, 'failed login')} in {_span(burst[0].ts, burst[-1].ts)}{where}, "
                f"mostly against " + ", ".join(f"'{u}' ({n})" for u, n in top) + ". "
                f"Internet-facing SSH sees this constantly, so on its own it is noise; "
                f"what matters is whether a login from this address follows.",
                ["T1110.001"], burst[0].ts, burst[-1].ts, burst[0].host, ip,
                evidence=_evidence(burst),
                why=f"{ip} brute-forced SSH with {_plural(attackers[ip].failures, 'failed login')}"))

    distributed = {}
    for user, evs in by_user.items():
        n_ips, win = peak_distinct(evs, th.distributed_window, key=lambda e: e.ip)
        if n_ips < th.distributed_ips:
            continue
        distributed[user] = win
        ips = sorted({e.ip for e in win})
        for ip in ips:
            if attackers[ip].label == "low volume":
                attackers[ip].label = "distributed"
        findings.append(Finding(
            "medium", "ssh.distributed", f"Distributed attack on account '{user}'",
            f"{_plural(n_ips, 'source')} failed to log in as '{user}' within "
            f"{_span(win[0].ts, win[-1].ts)}: {', '.join(ips[:6])}{' ...' if len(ips) > 6 else ''}. "
            f"Rotating sources defeats per-IP rate limits and fail2ban, so each address alone "
            f"looks harmless.",
            ["T1110.001"], win[0].ts, win[-1].ts, win[0].host, user=user,
            evidence=_evidence(win),
            why=f"{_plural(n_ips, 'address')} attacked the '{user}' account together"))
    return findings, attackers, labels, by_ip, distributed


# --------------------------------------------------------------------------- pass 2: compromise

def detect_logins(events, by_ip, labels, distributed, attackers, th):
    findings, incidents = [], []
    closes = defaultdict(list)
    for e in events:
        if e.kind == "ssh_session_close":
            closes[(e.host, e.pid)].append(e.ts)

    for a in (e for e in events if e.kind == "ssh_accept"):
        if a.ip in attackers:
            attackers[a.ip].successes.append(a.user)
        password = a.method in PASSWORD_METHODS
        prior = [f for f in by_ip.get(a.ip, []) if a.ts - th.compromise_lookback <= f.ts <= a.ts]
        trigger = None

        if len(prior) >= th.compromise_failures:
            users = Counter(f.user for f in prior)
            technique = "T1110.003" if labels.get(a.ip) == "password spray" else "T1110.001"
            how = ("the password for this account was guessed" if a.user in users else
                   "a password tried by the spray worked" if labels.get(a.ip) == "password spray"
                   else "it logged in as an account it had not been failing against")
            if password:
                detail = (f"{a.ip} failed {_plural(len(prior), 'time')} against "
                          f"{_plural(len(users), 'account')} in the preceding "
                          f"{_span(prior[0].ts, a.ts)}, then logged in as '{a.user}' with a "
                          f"password: {how}. Treat the account as compromised: reset its "
                          f"password, review what the session did, and block the address.")
            else:
                detail = (f"{a.ip} failed {_plural(len(prior), 'time')} and then logged in as "
                          f"'{a.user}' with {a.method}. A key login after password failures is "
                          f"less conclusive (a shared NAT address can mix a real user with an "
                          f"attacker), but the attacker may already hold a stolen key.")
            trigger = Finding(
                "critical" if password else "high", "ssh.compromise",
                f"Login as '{a.user}' after {_plural(len(prior), 'failed attempt')} from {a.ip}",
                detail, [technique, "T1078", "T1021.004"], a.ts, None, a.host, a.ip, a.user,
                actor=a.user, evidence=_evidence(prior[-4:] + [a]),
                why=(f"{a.ip} made {_plural(len(prior), 'failed login')} against "
                     f"{_plural(len(users), 'account')}, then logged in as '{a.user}' at "
                     f"{a.ts:%H:%M}"))
        elif password and a.user in distributed:
            win = distributed[a.user]
            if win[0].ts - th.compromise_lookback <= a.ts <= win[-1].ts + th.compromise_lookback:
                trigger = Finding(
                    "high", "ssh.distributed_success",
                    f"Password login as '{a.user}' during a distributed attack",
                    f"'{a.user}' was under attack from {len({e.ip for e in win})} sources when "
                    f"{a.ip} logged in with its password. This may be the real user, or one "
                    f"of the attack's guesses succeeding from a new address. Confirm with the "
                    f"account owner.",
                    ["T1110.001", "T1078", "T1021.004"], a.ts, None, a.host, a.ip, a.user,
                    actor=a.user, evidence=_evidence([a]),
                    why=f"{a.ip} logged in as '{a.user}' while that account was under attack")

        if a.user == "root":
            findings.append(Finding(
                "high" if password else "medium", "ssh.root_login",
                f"Direct root login over SSH from {a.ip}",
                f"Root logged in with {a.method}. Direct root logins leave no record of which "
                f"person acted; set PermitRootLogin no and use sudo"
                + (", and disable password authentication for root." if password else "."),
                ["T1078.003", "T1021.004"], a.ts, None, a.host, a.ip, "root", actor="root",
                evidence=_evidence([a]), why=f"root logged in directly from {a.ip}"))

        if trigger:
            findings.append(trigger)
            ends = sorted(t for t in closes.get((a.host, a.pid), []) if t >= a.ts)
            end = ends[0] if ends else a.ts + th.session_window
            inc = Incident(len(incidents) + 1, a.host, a.ip, a.user, a.ts, end, bool(ends), trigger)
            trigger.incident, trigger.end = inc.id, end
            incidents.append(inc)
    return findings, incidents


# --------------------------------------------------------------------------- pass 3: host activity

def detect_host_activity(events, th):
    findings = []
    denied, badpass, su_fail = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in events:
        d = e.detail
        if e.kind == "user_add":
            if d["uid"] == 0:
                findings.append(Finding(
                    "critical", "account.uid0", f"Second root account '{d['name']}' created (UID 0)",
                    f"'{d['name']}' was created with UID 0, home {d['home']} and shell {d['shell']}. "
                    f"Any UID 0 account is root under another name, a classic backdoor that "
                    f"survives a password reset of the real root.",
                    ["T1136.001", "T1078.003"], e.ts, host=e.host, user=d["name"],
                    evidence=_evidence([e]), why=f"created UID 0 account '{d['name']}'"))
            elif d["uid"] < 1000 and d["shell"].endswith(("nologin", "false")):
                continue    # a package installing a system account
            else:
                findings.append(Finding(
                    "low", "account.created", f"Local account '{d['name']}' created",
                    f"UID {d['uid']}, shell {d['shell']}. Expected if an administrator added it; "
                    f"check the change record.",
                    ["T1136.001"], e.ts, host=e.host, user=d["name"],
                    evidence=_evidence([e]), why=f"created account '{d['name']}'"))
        elif e.kind == "group_add" and d["group"] in PRIV_GROUPS:
            findings.append(Finding(
                "high", "account.priv_group", f"'{d['name']}' added to privileged group '{d['group']}'",
                f"Members of '{d['group']}' can become root"
                + (" by mounting the host filesystem into a container." if d["group"] in ("docker", "lxd")
                   else ".") + " Confirm the change was approved.",
                ["T1098"], e.ts, host=e.host, user=d["name"], actor=e.user or None,
                evidence=_evidence([e]), why=f"added '{d['name']}' to the '{d['group']}' group"))
        elif e.kind == "password_change":
            root = d["name"] == "root"
            findings.append(Finding(
                "medium" if root else "low", "account.password_change",
                f"Password changed for '{d['name']}'",
                "The root password was changed." if root else "Routine unless it happened during an incident.",
                ["T1098"], e.ts, host=e.host, user=d["name"],
                evidence=_evidence([e]), why=f"changed the password for '{d['name']}'"))
        elif e.kind == "user_delete":
            findings.append(Finding(
                "low", "account.deleted", f"Account '{d['name']}' deleted",
                "Deleting accounts can lock out administrators or remove evidence.",
                ["T1531"], e.ts, host=e.host, user=d["name"],
                evidence=_evidence([e]), why=f"deleted account '{d['name']}'"))
        elif e.kind == "sudo_cmd":
            for pattern, severity, title, mitre, why in SUSPICIOUS_COMMANDS:
                if pattern.search(d["command"]):
                    findings.append(Finding(
                        severity, "sudo.command", f"{title} (sudo by '{e.user}')",
                        f"Ran as {d['runas']} from {d['pwd'] or 'unknown directory'}: {d['command']}",
                        list(mitre), e.ts, host=e.host, user=e.user, actor=e.user,
                        evidence=_evidence([e]), why=why))
                    break
        elif e.kind == "sudo_denied":
            denied[(e.host, e.user)].append(e)
        elif e.kind == "sudo_badpass":
            badpass[(e.host, e.user)].append(e)
        elif e.kind == "su_fail":
            su_fail[(e.host, e.user)].append(e)

    for (host, user), evs in denied.items():
        commands = sorted({e.detail["command"] for e in evs})
        findings.append(Finding(
            "medium", "sudo.denied", f"'{user}' refused by sudo {_plural(len(evs), 'time')}",
            f"'{user}' is not allowed to run these as root: " + "; ".join(commands[:4])
            + ". Probing for privileges is typical right after an account is taken over.",
            ["T1548.003"], evs[0].ts, evs[-1].ts, host, user=user, actor=user,
            evidence=_evidence(evs), why=f"'{user}' tried to use sudo without permission"))
    for (host, user), evs in badpass.items():
        attempts = sum(e.detail.get("attempts", 1) for e in evs)
        if attempts >= th.sudo_failures:
            findings.append(Finding(
                "medium", "sudo.badpass", f"{_plural(attempts, 'wrong sudo password')} for '{user}'",
                f"Someone in a '{user}' session doesn't know that account's password, which "
                f"suggests the session was opened another way (a stolen key or token).",
                ["T1110.001", "T1548.003"], evs[0].ts, evs[-1].ts, host, user=user, actor=user,
                evidence=_evidence(evs), why=f"guessed sudo passwords as '{user}'"))
    for (host, user), evs in su_fail.items():
        if len(evs) >= th.su_failures:
            targets = sorted({e.detail["target"] for e in evs})
            findings.append(Finding(
                "medium", "su.bruteforce", f"{_plural(len(evs), 'failed su attempt')} by '{user}'",
                f"Repeated failures switching to {', '.join(targets)}: local password guessing.",
                ["T1110.001"], evs[0].ts, evs[-1].ts, host, user=user, actor=user,
                evidence=_evidence(evs), why=f"'{user}' guessed passwords with su"))
    return findings


# --------------------------------------------------------------------------- correlation

def correlate(findings, incidents):
    """Attach findings inside an incident's window to it, one severity level higher.

    useradd and usermod don't log who ran them, so an account change on the
    same host inside the window is attributed to the incident (actor None).
    sudo and su do log the user, and only that user's actions are attached.
    """
    for inc in incidents:
        for f in findings:
            if f.incident is not None or f is inc.trigger or f.host != inc.host:
                continue
            if inc.start <= f.ts <= inc.end and f.actor in (None, inc.user):
                if f.severity != "critical":
                    f.base_severity = f.severity
                    f.severity = SEVERITIES[RANK[f.severity] - 1]
                f.incident = inc.id
                f.detail = (f"During incident #{inc.id} (login as '{inc.user}' from {inc.ip}). "
                            + f.detail)
                inc.findings.append(f)
        inc.findings.sort(key=lambda f: f.ts)


def extract_iocs(findings, attackers, incidents):
    ips = sorted((a.ip for a in attackers.values()
                  if not a.internal and a.label != "low volume"),
                 key=lambda ip: (-attackers[ip].failures, ip))
    for inc in incidents:
        if not is_internal(inc.ip) and inc.ip not in ips:
            ips.append(inc.ip)
    accounts = sorted({f.user for f in findings if f.rule == "account.uid0"}
                      | {f.user for inc in incidents for f in inc.findings
                         if f.rule in ("account.created", "account.priv_group")})
    urls = sorted({u for f in findings if f.rule == "sudo.command" for u in URL_RE.findall(f.detail)})
    return {"ips": ips, "accounts": accounts, "urls": urls}


def summarize(findings, incidents, attackers, n_events, hosts):
    if incidents:
        inc = min(incidents, key=lambda i: (RANK[i.trigger.severity], i.start))
        text = inc.trigger.why[0].upper() + inc.trigger.why[1:] + "."
        clauses = list(dict.fromkeys(f.why for f in inc.findings if f.why))
        if clauses:
            span = _span(inc.start, inc.findings[-1].ts)
            text += (f" Within {span} the session " + ", ".join(clauses[:-1])
                     + (" and " if len(clauses) > 1 else "") + clauses[-1] + ".")
        if len(incidents) > 1:
            text += f" {_plural(len(incidents) - 1, 'more incident')} below."
        return text
    attacks = [f for f in findings if f.rule.startswith("ssh.") and f.rule != "ssh.root_login"]
    serious = [f for f in findings if RANK[f.severity] <= RANK["medium"]]
    if attacks:
        sources = sum(1 for a in attackers.values() if a.label != "low volume")
        text = (f"No successful attack found. {_plural(sources, 'source')} ran brute-force, "
                f"spraying or distributed attacks, and none of them logged in.")
        others = [f for f in serious if f not in attacks]
        if others:
            text += f" {_plural(len(others), 'other finding')} still {_verb(len(others))} review."
        return text
    if serious:
        return (f"No intrusion found, but {_plural(len(serious), 'finding')} {_verb(len(serious))} review, "
                f"starting with: {serious[0].title}.")
    return f"No threats found in {_plural(n_events, 'security event')} from {_plural(len(hosts), 'host')}."


def analyze(results, thresholds=None):
    """Run every detection over one or more ParseResults and build the final Analysis."""
    th = thresholds or Thresholds()
    events = sorted((e for r in results for e in r.events), key=lambda e: e.ts)
    attempts = failed_attempts(events)

    findings, attackers, labels, by_ip, distributed = detect_attacks(attempts, th)
    login_findings, incidents = detect_logins(events, by_ip, labels, distributed, attackers, th)
    findings += login_findings + detect_host_activity(events, th)
    correlate(findings, incidents)
    findings.sort(key=lambda f: (RANK[f.severity], f.ts))

    hosts = sorted({e.host for e in events})
    worst = findings[0].severity if findings else "info"
    stats = {"lines": sum(r.lines for r in results),
             "recognized": sum(r.recognized for r in results),
             "unparsed": sum(len(r.unparsed) for r in results),
             "events": len(events), "failed_logins": len(attempts),
             "successful_logins": sum(1 for e in events if e.kind == "ssh_accept"),
             "sudo_commands": sum(1 for e in events if e.kind == "sudo_cmd")}
    return Analysis(
        sources=[r.source for r in results],
        hosts=hosts, stats=stats,
        first=events[0].ts if events else None, last=events[-1].ts if events else None,
        findings=findings, incidents=incidents,
        attackers=sorted(attackers.values(), key=lambda a: (-bool(a.successes), -a.failures, a.ip)),
        iocs=extract_iocs(findings, attackers, incidents),
        verdict=VERDICTS.get(worst, CLEAN),
        summary=summarize(findings, incidents, attackers, len(events), hosts),
        failures_timeline=[e.ts for e in attempts])
