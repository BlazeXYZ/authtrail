"""Command-line entry point: python -m authtrail [paths ...]"""

import argparse
import gzip
import os
import sys
from pathlib import Path

from . import __version__
from .detections import RANK, SEVERITIES, Thresholds, analyze
from .parser import parse_text
from .report import to_html, to_json, to_terminal

LOG_PATTERNS = ("auth.log*", "secure*", "*.log", "*.log.gz")
FAIL_ON = SEVERITIES[:4] + ("never",)


def read_log(path):
    """Read a log file as text. Rotated logs may be gzipped.

    Invalid UTF-8 is replaced rather than fatal: attackers can send arbitrary
    bytes as a username, and one bad byte must not hide the rest of the file.
    """
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", errors="replace")


def can_encode(stream, text):
    try:
        text.encode(stream.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def collect_inputs(paths):
    """Yield (name, text) for each file, every log in each folder, or stdin for "-"."""
    for item in paths:
        if item == "-":
            yield "<stdin>", sys.stdin.read()
            continue
        path = Path(item)
        if path.is_dir():
            files = sorted({f for pattern in LOG_PATTERNS for f in path.glob(pattern) if f.is_file()})
            if not files:
                print(f"authtrail: no log files in {path}", file=sys.stderr)
            for f in files:
                yield f.name, read_log(f)
        elif path.is_file():
            yield path.name, read_log(path)
        else:
            print(f"authtrail: not found: {path}", file=sys.stderr)


def build_parser():
    p = argparse.ArgumentParser(
        prog="authtrail",
        description="Hunt for SSH attacks, compromises and post-compromise activity in Linux auth logs.",
        epilog="Exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above it, 2 = error.")
    p.add_argument("paths", nargs="+", help="auth.log / secure files (gzip ok), folders, or - for stdin")
    p.add_argument("--year", type=int, help="year of the first BSD-syslog line (default: inferred)")
    p.add_argument("--html", metavar="FILE", help="write a standalone HTML report")
    p.add_argument("--json", metavar="FILE", help="write JSON (use - for stdout instead of the text report)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this")
    p.add_argument("--fail-on", choices=FAIL_ON, default="high",
                   help="exit 1 when a finding is at or above this severity (default: high)")
    p.add_argument("--no-color", action="store_true", help="plain text output")
    g = p.add_argument_group("detection thresholds")
    d = Thresholds()
    g.add_argument("--brute-threshold", type=int, default=d.brute_failures,
                   help=f"failures from one source in {d.brute_window.seconds // 60} min (default {d.brute_failures})")
    g.add_argument("--spray-users", type=int, default=d.spray_users,
                   help=f"accounts tried by one source in {d.spray_window.seconds // 60} min (default {d.spray_users})")
    g.add_argument("--distributed-ips", type=int, default=d.distributed_ips,
                   help=f"sources failing against one account in an hour (default {d.distributed_ips})")
    g.add_argument("--compromise-failures", type=int, default=d.compromise_failures,
                   help=f"failures before a success that make it a compromise (default {d.compromise_failures})")
    p.add_argument("--version", action="version", version=f"authtrail {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    # Hostile usernames can contain any character; never crash on a console that can't print it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    results = [parse_text(text, name, year=args.year) for name, text in collect_inputs(args.paths)]
    if not results:
        print("authtrail: no input could be read", file=sys.stderr)
        return 2
    if not any(r.recognized for r in results):
        print("authtrail: no lines in a recognized syslog format; is this an auth log?", file=sys.stderr)
        return 2

    th = Thresholds(brute_failures=args.brute_threshold, spray_users=args.spray_users,
                    distributed_ips=args.distributed_ips, compromise_failures=args.compromise_failures)
    analysis = analyze(results, th)

    if args.json == "-":
        print(to_json(analysis))
    else:
        color = not args.no_color and (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR")))
        print(to_terminal(analysis, color=color, min_severity=args.min_severity,
                          fancy=can_encode(sys.stdout, "─▁█→·")))
        if args.json:
            Path(args.json).write_text(to_json(analysis), encoding="utf-8")
            print(f"JSON written to {args.json}")
    if args.html:
        Path(args.html).write_text(to_html(analysis), encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr if args.json == "-" else sys.stdout)

    if args.fail_on != "never" and any(RANK[f.severity] <= RANK[args.fail_on] for f in analysis.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
