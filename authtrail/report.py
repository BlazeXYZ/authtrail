"""Render an Analysis as terminal text, JSON, or a standalone HTML page.

Usernames, commands and hostnames in auth logs are attacker-controlled: anyone
can attempt an SSH login as "<script>..." or with terminal escape codes in the
name. Every value is passed through `clean()` (control characters made
visible) before display, and through `html.escape` for HTML. The HTML report
contains no JavaScript at all.
"""

import json
import re
import textwrap
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta
from html import escape

from . import __version__
from .detections import MITRE, RANK, SEVERITIES

ANSI = {"critical": "\033[97;41m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
        "info": "\033[90m", "bold": "\033[1m", "dim": "\033[2m", "green": "\033[92m",
        "reset": "\033[0m"}
VERDICT_COLOR = {"COMPROMISE LIKELY": "critical", "HIGH RISK": "high", "SUSPICIOUS": "medium",
                 "NO THREATS FOUND": "green"}
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
BUCKET_MINUTES = (1, 5, 10, 15, 30, 60, 120, 360, 720, 1440)
# Box-drawing and block characters, with ASCII stand-ins for consoles that can't encode them
# (a redirected Windows console defaults to cp1252).
SYMBOLS = {True: {"rule": "─", "dot": "·", "arrow": "→", "spark": " ▁▂▃▄▅▆▇█"},
           False: {"rule": "-", "dot": "|", "arrow": "->", "spark": " .:-=+*#@"}}


def clean(value):
    """Make control characters visible, so a hostile username can't drive the terminal."""
    return CONTROL_RE.sub(lambda m: f"\\x{ord(m[0]):02x}", str(value))


def mitre_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def defang(kind, value):
    if kind == "ips":
        return value.replace(":", "[:]") if ":" in value else value.replace(".", "[.]")
    if kind == "urls":
        return value.replace("http", "hxxp", 1).replace(".", "[.]")
    return value


def activity(times, max_buckets=48):
    """Bucket failed-login timestamps for the activity chart: (bucket minutes, start, counts)."""
    if not times:
        return 0, None, []
    first, last = min(times), max(times)
    span = (last - first).total_seconds() / 60
    size = next((b for b in BUCKET_MINUTES if span / b < max_buckets), BUCKET_MINUTES[-1])
    midnight = first.replace(hour=0, minute=0, second=0, microsecond=0)
    start = midnight + timedelta(minutes=(first - midnight).total_seconds() // 60 // size * size)
    counts = [0] * (int((last - start).total_seconds() // 60 // size) + 1)
    for t in times:
        counts[int((t - start).total_seconds() // 60 // size)] += 1
    return size, start, counts


def _bucket_label(minutes):
    return f"{minutes} min" if minutes < 60 else f"{minutes // 60} h" if minutes < 1440 else "day"


def _severity_counts(findings):
    counts = Counter(f.severity for f in findings)
    return ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])


# --------------------------------------------------------------------------- terminal

def to_terminal(a, color=True, min_severity="low", fancy=True):
    c = (lambda key: ANSI[key]) if color else (lambda key: "")
    sym = SYMBOLS[fancy]
    dot, arrow = f"  {sym['dot']}  ", sym["arrow"]
    line = c("dim") + sym["rule"] * 76 + c("reset")
    shown = [f for f in a.findings if RANK[f.severity] <= RANK[min_severity]]
    out = [line, f"{c('bold')}authtrail{c('reset')}  {clean(', '.join(a.sources))}",
           f"{c(VERDICT_COLOR[a.verdict])}{c('bold')} {a.verdict} {c('reset')}  "
           + (f"{len(a.findings)} findings ({_severity_counts(a.findings)})" if a.findings else "no findings")]
    out += textwrap.wrap(clean(a.summary), 76)
    out.append(line)

    s = a.stats
    if a.first:
        out.append(f"Hosts {clean(', '.join(a.hosts))}{dot}{a.first:%Y-%m-%d %H:%M} {arrow} {a.last:%Y-%m-%d %H:%M}")
    out.append(f"{s['lines']} lines, {s['events']} security events{dot}{s['failed_logins']} failed / "
               f"{s['successful_logins']} successful SSH logins{dot}{s['sudo_commands']} sudo command{'' if s['sudo_commands'] == 1 else 's'}"
               + (f"{dot}{c('medium')}{s['unparsed']} unrecognized lines{c('reset')}" if s["unparsed"] else ""))
    size, start, counts = activity(a.failures_timeline, max_buckets=60)
    if counts:
        peak = max(counts)
        bars = sym["spark"]
        spark = "".join(bars[0 if n == 0 else 1 + round(n / peak * (len(bars) - 2))] for n in counts)
        out.append(f"Failed logins per {_bucket_label(size)} from {start:%H:%M}: "
                   f"{c('high')}{spark}{c('reset')} peak {peak}")
    out.append(line)

    for inc in a.incidents:
        state = "session closed" if inc.session_closed else "session close not seen"
        out.append(f"{c('critical')}{c('bold')} INCIDENT #{inc.id} {c('reset')}  {clean(inc.host)}: "
                   f"'{clean(inc.user)}' from {clean(inc.ip)}  {inc.start:%H:%M:%S} {arrow} {inc.end:%H:%M:%S} ({state})")
        for f in [inc.trigger] + inc.findings:
            out.append(f"  {f.ts:%H:%M:%S}  {c(f.severity)}{f.severity.upper():<8}{c('reset')} {clean(f.title)}")
        out.append(line)

    if shown:
        out.append(f"{c('bold')}FINDINGS{c('reset')}")
    for f in shown:
        badge = f"{c(f.severity)}{c('bold')}[{f.severity.upper()}]{c('reset')}"
        raised = f" {c('dim')}(raised from {f.base_severity}){c('reset')}" if f.base_severity else ""
        out.append(f"{badge} {clean(f.title)}{raised}")
        out.extend(textwrap.wrap(clean(f.detail), 72, initial_indent="    ", subsequent_indent="    "))
        out.append(f"    {c('dim')}{f.ts:%Y-%m-%d %H:%M:%S}{dot}{clean(f.host)}{dot}ATT&CK "
                   + ", ".join(f"{t} {MITRE.get(t, '')}" for t in f.mitre) + c("reset"))
        out.append(f"    {c('dim')}evidence: " + ", ".join(f"{clean(src)}:{n}" for src, n in f.evidence)
                   + c("reset"))
    if len(shown) < len(a.findings):
        out.append(f"{c('dim')}{len(a.findings) - len(shown)} lower-severity findings hidden "
                   f"(--min-severity){c('reset')}")

    attackers = [x for x in a.attackers if x.label != "low volume"]
    if attackers:
        out += [line, f"{c('bold')}ATTACK SOURCES{c('reset')}",
                f"  {'address':<26} {'pattern':<15} {'fails':>5} {'accts':>5}  logged in as"]
        for x in attackers[:15]:
            got_in = ", ".join(sorted(set(x.successes))) or "-"
            out.append(f"  {clean(x.ip):<26} {x.label:<15} {x.failures:>5} {len(x.users):>5}  "
                       f"{c('critical') if x.successes else ''}{clean(got_in)}{c('reset') if x.successes else ''}")
    if any(a.iocs.values()):
        out += [line, f"{c('bold')}INDICATORS{c('reset')} (defanged)"]
        for kind, values in a.iocs.items():
            if values:
                out.append(f"  {kind:<9} " + ", ".join(clean(defang(kind, v)) for v in values))
    out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------- JSON

def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Counter):
        return dict(value.most_common())
    raise TypeError(f"not serializable: {type(value).__name__}")


def to_dict(a):
    """Machine-readable form. Values are raw (not defanged), as SOAR and SIEM tools expect."""
    def finding(f):
        d = asdict(f)
        d["mitre"] = [{"id": t, "name": MITRE.get(t, "")} for t in f.mitre]
        d["evidence"] = [{"source": src, "line": n} for src, n in f.evidence]
        return d

    return {
        "tool": "authtrail", "version": __version__,
        "verdict": a.verdict, "summary": a.summary,
        "sources": a.sources, "hosts": a.hosts, "stats": a.stats,
        "first_event": a.first, "last_event": a.last,
        "incidents": [{"id": i.id, "host": i.host, "ip": i.ip, "user": i.user, "start": i.start,
                       "end": i.end, "session_closed": i.session_closed,
                       "findings": [i.trigger.rule] + [f.rule for f in i.findings]} for i in a.incidents],
        "findings": [finding(f) for f in a.findings],
        "attack_sources": [{"ip": x.ip, "internal": x.internal, "pattern": x.label,
                            "failures": x.failures, "accounts": x.users, "logged_in_as": x.successes,
                            "first": x.first, "last": x.last, "hosts": x.hosts} for x in a.attackers],
        "iocs": a.iocs,
    }


def to_json(a):
    return json.dumps(to_dict(a), indent=2, default=_jsonable, ensure_ascii=False)


# --------------------------------------------------------------------------- HTML

CSS = """
:root{--bg:#f6f7fb;--card:#fff;--text:#1d2330;--muted:#5d6678;--line:#e3e6ee;
--critical:#b4232c;--high:#d9480f;--medium:#b7791f;--low:#1c7ed6;--info:#6b7280;--ok:#2b8a3e;--bar:#e8590c}
@media (prefers-color-scheme:dark){:root{--bg:#11141b;--card:#1a1f2a;--text:#e6e9f0;--muted:#9aa3b5;
--line:#2a3140;--critical:#ff6b6b;--high:#ff922b;--medium:#fcc419;--low:#4dabf7;--ok:#51cf66;--bar:#ff922b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0}h2{font-size:17px;margin:28px 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.verdict{border-left:6px solid var(--v)}.verdict .label{color:var(--v);font-weight:800;font-size:20px;letter-spacing:.02em}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.tile b{display:block;font-size:22px}.tile span{color:var(--muted);font-size:13px}
.sev{display:inline-block;min-width:74px;text-align:center;border-radius:4px;padding:1px 6px;font-size:12px;
font-weight:700;color:#fff;background:var(--s)}
.sev.medium{color:#1d2330}
.critical{--s:var(--critical)}.high{--s:var(--high)}.medium{--s:var(--medium)}.low{--s:var(--low)}.info{--s:var(--info)}
.finding{border-left:4px solid var(--s)}.finding h3{font-size:15px;margin:0 0 6px}
.finding p{margin:6px 0}.tags a{color:var(--muted);font-size:13px;margin-right:10px}
.chart{display:flex;align-items:flex-end;gap:2px;height:110px;padding-top:8px;border-bottom:1px solid var(--line)}
.chart div{flex:1;background:var(--bar);border-radius:2px 2px 0 0;min-height:1px}
.axis{display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.scroll{overflow-x:auto}.timeline td:first-child{white-space:nowrap}
"""


def e(value):
    return escape(clean(value), quote=True)


def to_html(a, generated=None):
    generated = generated or datetime.now()
    vcolor = {"COMPROMISE LIKELY": "var(--critical)", "HIGH RISK": "var(--high)",
              "SUSPICIOUS": "var(--medium)", "NO THREATS FOUND": "var(--ok)"}[a.verdict]
    s = a.stats
    span = f"{a.first:%Y-%m-%d %H:%M} → {a.last:%Y-%m-%d %H:%M}" if a.first else "no events"
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>authtrail report: {e(a.verdict)}</title><style>{CSS}</style></head><body><main>
<h1>authtrail</h1><p class="muted mono">{e(', '.join(a.sources))} · hosts {e(', '.join(a.hosts) or '-')} · {e(span)}</p>
<div class="card verdict" style="--v:{vcolor}"><div class="label">{e(a.verdict)}</div>
<p>{e(a.summary)}</p></div>
<div class="tiles">"""]
    for value, label in [(len(a.findings), "findings"), (len(a.incidents), "incidents"),
                         (s["failed_logins"], "failed SSH logins"), (s["successful_logins"], "successful logins"),
                         (sum(1 for x in a.attackers if x.label != "low volume"), "attack sources"),
                         (s["events"], f"events from {s['lines']} lines")]:
        parts.append(f'<div class="tile"><b>{value}</b><span>{e(label)}</span></div>')
    parts.append("</div>")

    size, start, counts = activity(a.failures_timeline)
    if counts:
        peak = max(counts)
        parts.append(f'<h2>Failed logins per {e(_bucket_label(size))}</h2><div class="card"><div class="chart">')
        for i, n in enumerate(counts):
            t = start + timedelta(minutes=i * size)
            parts.append(f'<div style="height:{n / peak * 100:.1f}%" title="{t:%m-%d %H:%M}: {n}"></div>')
        end = start + timedelta(minutes=len(counts) * size)
        parts.append(f'</div><div class="axis"><span>{start:%m-%d %H:%M}</span><span>peak {peak}</span>'
                     f'<span>{end:%m-%d %H:%M}</span></div></div>')

    for inc in a.incidents:
        state = "session closed" if inc.session_closed else "no session close seen; window capped"
        parts.append(f'<h2>Incident #{inc.id}: \'{e(inc.user)}\' from {e(inc.ip)} on {e(inc.host)}</h2>'
                     f'<div class="card scroll"><p class="muted">{inc.start:%Y-%m-%d %H:%M:%S} → '
                     f'{inc.end:%H:%M:%S} ({e(state)})</p><table class="timeline">'
                     f'<tr><th>Time</th><th>Severity</th><th>What happened</th></tr>')
        for f in [inc.trigger] + inc.findings:
            parts.append(f'<tr><td class="mono">{f.ts:%H:%M:%S}</td><td><span class="sev {f.severity}">'
                         f'{f.severity.upper()}</span></td><td>{e(f.title)}</td></tr>')
        parts.append("</table></div>")

    parts.append(f"<h2>Findings ({len(a.findings)})</h2>")
    if not a.findings:
        parts.append('<div class="card muted">No findings.</div>')
    for f in a.findings:
        raised = f' <span class="muted">(raised from {e(f.base_severity)})</span>' if f.base_severity else ""
        tags = "".join(f'<a href="{mitre_url(t)}" rel="noopener noreferrer">{t} {e(MITRE.get(t, ""))}</a>'
                       for t in f.mitre)
        evidence = ", ".join(f"{e(src)}:{n}" for src, n in f.evidence)
        parts.append(f'<div class="card finding {f.severity}"><h3><span class="sev {f.severity}">'
                     f'{f.severity.upper()}</span> {e(f.title)}{raised}</h3><p>{e(f.detail)}</p>'
                     f'<p class="muted mono">{f.ts:%Y-%m-%d %H:%M:%S} · {e(f.host)} · evidence {evidence}</p>'
                     f'<p class="tags">{tags}</p></div>')

    if a.attackers:
        parts.append('<h2>Sources of failed logins</h2><div class="card scroll"><table><tr><th>Address</th>'
                     '<th>Pattern</th><th>Failures</th><th>Accounts tried</th><th>Logged in as</th>'
                     '<th>First → last</th></tr>')
        for x in a.attackers[:50]:
            top = ", ".join(f"{u} ({n})" for u, n in x.users.most_common(4))
            more = f" +{len(x.users) - 4} more" if len(x.users) > 4 else ""
            parts.append(f'<tr><td class="mono">{e(x.ip)}{" (internal)" if x.internal else ""}</td>'
                         f'<td>{e(x.label)}</td><td>{x.failures}</td><td class="mono">{e(top + more)}</td>'
                         f'<td class="mono">{e(", ".join(sorted(set(x.successes))) or "-")}</td>'
                         f'<td class="mono">{x.first:%m-%d %H:%M} → {x.last:%H:%M}</td></tr>')
        parts.append("</table></div>")

    if any(a.iocs.values()):
        parts.append('<h2>Indicators (defanged)</h2><div class="card"><table>')
        for kind, values in a.iocs.items():
            if values:
                parts.append(f'<tr><th>{e(kind)}</th><td class="mono">'
                             + "<br>".join(e(defang(kind, v)) for v in values) + "</td></tr>")
        parts.append("</table></div>")

    parts.append(f'<p class="muted">{s["recognized"]} of {s["lines"]} lines in a recognized syslog format'
                 + (f", {s['unparsed']} unrecognized" if s["unparsed"] else "")
                 + f". Generated by authtrail {__version__} on {generated:%Y-%m-%d %H:%M}. "
                 "Times are as logged: BSD syslog lines in the server's local time, RFC 3339 lines in UTC.</p>"
                 "</main></body></html>")
    return "".join(parts)
