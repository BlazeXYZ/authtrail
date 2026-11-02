# Changelog

## 1.0.0

First release.

### Detections
- **Attacks:** SSH brute force, password spraying, username probing against key-only servers, and distributed attacks on a single account, all using O(n) sliding windows.
- **Compromise:** a successful login after failures from the same source (CRITICAL for passwords, HIGH for keys), and password logins to an account under distributed attack.
- **Incidents:** each compromise opens an incident that lasts until the matching SSH session closes. Findings inside it are raised one severity level and shown as a timeline.
- **Host activity:** UID 0 accounts, new accounts, privileged groups (including `docker` and `lxd`), password changes, deleted accounts, refused sudo, wrong sudo and su passwords, and twelve risky sudo command patterns (download-and-execute, reverse shells, log wiping, disabled firewalls and security tools, setuid, shadow access, authorized_keys, cron, sudoers, services, root shells).
- MITRE ATT&CK IDs on every finding.

### Parsing
- BSD syslog and RFC 3339 timestamps; year rollover and inference; `message repeated N times` expansion; `Invalid user` deduplication by sshd PID; OpenSSH 9.8's `sshd-session`; IPv4-mapped IPv6; gzipped rotated logs.

### Reports
- Terminal (with an ASCII fallback), JSON (raw values) and self-contained HTML (no JavaScript), plus a plain-English summary and defanged IOCs.

### Security
- End-anchored sshd patterns, so a username can't spoof the logged source address.
- HTML escaping and terminal control-character neutralization for attacker-controlled usernames and commands.

### Testing
- 44 tests, mutation-checked on the key defenses. CI runs on Ubuntu and Windows with Python 3.11, 3.13 and 3.14.
