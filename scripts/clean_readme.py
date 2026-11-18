#!/usr/bin/env python3
"""
Self-cleaning subscription list.

Checks every subscription link inside the code blocks of README.md and removes a
link ONLY after it has failed in a confirmed way on several different days.
Everything else in the README stays byte-for-byte identical (only the link lines
are removed and, optionally, the "last updated" date is refreshed).

Verdicts per link
  ok       opens and contains configs (or a list of links)       -> strikes reset
  hard     404/410, domain does not exist, empty / no configs    -> removed after STRIKES day(s)
  unreach  timeout, refused, TLS error, 5xx                      -> strike (STRIKES_UNREACH days)
  soft     401/403/429, temporary DNS error                      -> ignored, nothing changes

Environment variables (all optional)
  README, STATE, KEEP            file paths
  STRIKES=1  STRIKES_UNREACH=7  STRIKES_EMPTY=3   days of consecutive failure before removal
  MAX_REMOVE_RATIO=0.3           refuse to remove more than this share in one run
  UPDATE_DATE=changed|always|never   (changed = refresh date only when links were removed)
  DRY_RUN=1                      report only, change nothing
  COUNTS_ONLY=1                  no network checks: only fix the numbers in the README (used on every push)

The numbers in the README are ALWAYS recomputed from the real content, whether links were
removed automatically or added by hand: per-section "**N links.**", the total
"**N free public ...**" and the repository count ("**N open-source GitHub repositories**").
"""
import base64
import datetime as dt
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

README = os.environ.get("README", "README.md")
STATE = os.environ.get("STATE", ".github/sub-health.json")
KEEP = os.environ.get("KEEP", ".github/sub-keep.txt")
STRIKES = int(os.environ.get("STRIKES", "1"))
STRIKES_UNREACH = int(os.environ.get("STRIKES_UNREACH", "7"))
STRIKES_EMPTY = int(os.environ.get("STRIKES_EMPTY", "3"))  # page opens but has no configs (may be a temporary empty list)
MAX_RATIO = float(os.environ.get("MAX_REMOVE_RATIO", "0.3"))
UPDATE_DATE = os.environ.get("UPDATE_DATE", "changed")
WORKERS = int(os.environ.get("WORKERS", "16"))
TIMEOUT = int(os.environ.get("TIMEOUT", "25"))
DRY = os.environ.get("DRY_RUN") == "1"
MAX_BYTES = 8 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; sub-health-check/1.0)"

NOW = dt.datetime.now(dt.timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")

# ---------------------------------------------------------------- content check
LINK = re.compile(
    r"(?<![A-Za-z0-9])(?:vmess|vless|trojan|ssr?|hysteria2?|hy2|tuic|wireguard)://[^\s\"'<>]{8,}"
    r"|https?://t\.me/proxy\?[^\s\"'<>]+|tg://proxy\?[^\s\"'<>]+",
    re.I,
)
STRUCT = re.compile(r"[\"']?\b(?:server|address)[\"']?\s*:\s*[\"']?[\w.\-:\[\]\\]{3,}")  # \\ allows "\x32\x2e..." escaped hosts


def has_configs(text, depth=0):
    if LINK.search(text):
        return True
    s = text.strip()
    if (re.search(r"^proxies\s*:", s, re.M) or s[:1] in "[{" or "outbounds" in s
            or re.search(r"^\s*-\s*\{?\s*(?:name|type|server)\s*:", s, re.M)):
        if STRUCT.search(s):
            return True
    if depth < 2:
        z = re.sub(r"\s+", "", s)
        if len(z) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", z):
            try:
                z = z.replace("-", "+").replace("_", "/")
                z += "=" * (-len(z) % 4)
                dec = base64.b64decode(z).decode("utf-8", "ignore")
                return has_configs(dec, depth + 1)
            except Exception:
                return False
    return False


def content_verdict(data):
    text = data[:MAX_BYTES].decode("utf-8", "ignore")
    if not text.strip():
        return "empty"
    if has_configs(text):
        return "ok"
    is_html = bool(re.search(r"<(!doctype|html)", text[:800], re.I))
    if not is_html and len(re.findall(r"https?://\S+", text)) >= 3:
        return "ok"  # a list of other subscription links
    return "noconfigs"


# ---------------------------------------------------------------------- probing
NX = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)}


def fetch(url):
    safe = urllib.parse.quote(url, safe=":/?&=%#+@!$,;~[]")
    req = urllib.request.Request(safe, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read(MAX_BYTES + 1)


def probe(url):
    last = ("soft", "?")
    for attempt in range(3):
        try:
            v = content_verdict(fetch(url))
            if v == "ok":
                return "ok", "OK"
            last = ("hard", v)
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                last = ("hard", f"HTTP {e.code}")
            elif e.code >= 500:
                last = ("unreach", f"HTTP {e.code}")
            else:
                return "soft", f"HTTP {e.code}"
        except urllib.error.URLError as e:
            r = e.reason
            if isinstance(r, socket.gaierror):
                last = ("hard", "DNS") if r.errno in NX else ("soft", "DNS temporary")
            else:
                last = ("unreach", type(r).__name__)
        except Exception as e:  # timeouts, resets, TLS...
            last = ("unreach", type(e).__name__)
        if attempt < 2:
            time.sleep((3, 8)[attempt])
    return last


# ------------------------------------------------------------------ README parse
URL_RE = re.compile(r"^(https?://\S+)$")


def link_lines(lines):
    inc, out = False, []
    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith(("```", "~~~")):
            inc = not inc
            continue
        if inc:
            m = URL_RE.match(s)
            if m:
                out.append((i, m.group(1).split("#")[0]))
    return out


# ------------------------------------------------- empty code blocks / headings
HEAD = re.compile(r"^(#{1,6})\s")


def drop_empty_blocks(lines):
    """Remove fenced blocks left empty after link removal, plus the heading above
    them if its whole section is now empty. Untouched parts stay as they were."""
    out, pos, i = [], [], 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith(("```", "~~~")):
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(s[:3]):
                j += 1
            if j < len(lines) and all(not x.strip() for x in lines[i + 1:j]):
                pos.append(len(out))
                i = j + 1
                continue
        out.append(lines[i])
        i += 1
    for p in sorted(set(pos), reverse=True):
        h = p - 1
        while h >= 0 and not out[h].strip():
            h -= 1
        n = p
        while n < len(out) and not out[n].strip():
            n += 1
        m = HEAD.match(out[h]) if h >= 0 else None
        nxt = HEAD.match(out[n]) if n < len(out) else None
        if m and (n >= len(out) or (nxt and len(nxt.group(1)) <= len(m.group(1)))):
            del out[h:n]
        elif 0 < p < len(out) and not out[p - 1].strip() and not out[p].strip():
            del out[p]
    return out, len(pos)


# ------------------------------------------------------------ link counters
COUNT_SEC = re.compile(r"(\*\*)\d[\d,]*( links\.\*\*)")
COUNT_TOT = re.compile(r"(\*\*)\d[\d,]*( free public)")


def update_counts(lines):
    """Refresh '**N links.**' above each code block and the total in the intro."""
    out, total, changed = list(lines), 0, 0
    i = 0
    while i < len(out):
        if out[i].strip().startswith(("```", "~~~")):
            fence = out[i].strip()[:3]
            j = i + 1
            n = 0
            while j < len(out) and not out[j].strip().startswith(fence):
                if URL_RE.match(out[j].strip()):
                    n += 1
                j += 1
            total += n
            for k in range(i - 1, max(i - 6, -1), -1):
                new = COUNT_SEC.sub(lambda m: f"{m.group(1)}{n}{m.group(2)}", out[k])
                if new != out[k]:
                    out[k], changed = new, changed + 1
                    break
            i = j + 1
        else:
            i += 1
    inc = False
    for k, l in enumerate(out):
        if l.strip().startswith(("```", "~~~")):
            inc = not inc
        elif not inc:
            new = COUNT_TOT.sub(lambda m: f"{m.group(1)}{total}{m.group(2)}", l)
            if new != l:
                out[k], changed = new, changed + 1
    return out, changed


REPO_BUL = re.compile(r"^- \[[^\]]+\]\(https://github\.com/[^)\s]+\)\s*$")
REPO_A = re.compile(r"(\*\*)\d[\d,]*( open-source GitHub repositories)")
REPO_B = re.compile(r"(Show all )\d[\d,]*( source repositories)")


def update_repo_count(lines):
    """Count the bullets in 'Sources and Credits' and refresh the repository numbers."""
    start = next((i for i, l in enumerate(lines) if l.startswith("## Sources and Credits")), None)
    if start is None:
        return lines, 0
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    n = sum(1 for l in lines[start:end] if REPO_BUL.match(l.strip()))
    out, changed, inc = list(lines), 0, False
    for k, l in enumerate(out):
        if l.strip().startswith(("```", "~~~")):
            inc = not inc
            continue
        if inc:
            continue
        new = REPO_B.sub(lambda m: f"{m.group(1)}{n}{m.group(2)}", REPO_A.sub(lambda m: f"{m.group(1)}{n}{m.group(2)}", l))
        if new != l:
            out[k], changed = new, changed + 1
    return out, changed


# ------------------------------------------------------------------------ dates
DIG = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
FA = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
KEY = re.compile(r"(updat|آخرین|بروز|به‌?روز|آپدیت|تاریخ|last|modified|refresh)", re.I)
DATE = re.compile(
    r"(?<!\d)(\d{4})([-/.])(\d{1,2})\2(\d{1,2})(?:([ T]+)(\d{1,2}):(\d{2})(?::(\d{2}))?)?(?!\d)"
)
MARK = re.compile(r"(<!--\s*updated\s*-->)(.*?)(<!--\s*/updated\s*-->)")


def g2j(gy, gm, gd):
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = (355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100
            + (gy2 + 399) // 400 + gd + g_d_m[gm - 1])
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm, jd = 1 + days // 31, 1 + days % 31
    else:
        jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
    return jy, jm, jd


def render_date(m, span):
    y = int(m.group(1))
    jal = 1300 <= y <= 1500
    t = NOW + dt.timedelta(hours=3, minutes=30) if jal else NOW
    Y, M, D = g2j(t.year, t.month, t.day) if jal else (t.year, t.month, t.day)
    sep = m.group(2)
    mo = f"{M:02d}" if len(m.group(3)) == 2 else str(M)
    da = f"{D:02d}" if len(m.group(4)) == 2 else str(D)
    s = f"{Y}{sep}{mo}{sep}{da}"
    if m.group(6) is not None:
        s += f"{m.group(5)}{t.hour:02d}:{t.minute:02d}"
        if m.group(8) is not None:
            s += f":{t.second:02d}"
    return s.translate(FA) if not span.isascii() else s


def bump_dates(lines):
    inc, done, out = False, 0, []
    for l in lines:
        if l.strip().startswith(("```", "~~~")):
            inc = not inc
            out.append(l)
            continue
        if inc:
            out.append(l)
            continue
        n = MARK.sub(lambda m: f"{m.group(1)}{NOW:%Y-%m-%d %H:%M} UTC{m.group(3)}", l)
        if n != l:
            done += 1
        elif KEY.search(l):
            m = DATE.search(l.translate(DIG))
            if m and (2000 <= int(m.group(1)) <= 2100 or 1300 <= int(m.group(1)) <= 1500) \
                    and 1 <= int(m.group(3)) <= 12 and 1 <= int(m.group(4)) <= 31:
                n = l[:m.start()] + render_date(m, l[m.start():m.end()]) + l[m.end():]
                done += 1
        out.append(n)
    return out, done


# ------------------------------------------------------------------------- main
def load_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_keep():
    try:
        with open(KEEP, encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")]
    except Exception:
        return []


def main():
    if not os.path.exists(README):
        sys.exit(f"{README} not found")
    with open(README, encoding="utf-8", newline="") as f:
        raw = f.read()
    lines = raw.splitlines(keepends=True)
    if os.environ.get("COUNTS_ONLY") == "1":
        new_lines, a = update_counts(lines)
        new_lines, b = update_repo_count(new_lines)
        print(f"COUNTS_ONLY: {a + b} number(s) refreshed")
        if not DRY and "".join(new_lines) != raw:
            with open(README, "w", encoding="utf-8", newline="") as f:
                f.write("".join(new_lines))
        return
    urls = sorted({u for _, u in link_lines(lines)})
    keep, state = load_keep(), load_json(STATE)
    print(f"{len(urls)} links found")

    with ThreadPoolExecutor(WORKERS) as ex:
        res = dict(zip(urls, ex.map(probe, urls)))

    n = len(urls)
    flaky = sum(1 for v, _ in res.values() if v in ("soft", "unreach"))
    inconclusive = n > 0 and flaky > n * 0.5
    notes = []
    new_state, cands = {}, []

    if inconclusive:
        notes.append("More than half of the links were unreachable: probably a network problem on the runner. "
                     "Nothing was changed.")
        new_state = state
    else:
        for u in urls:
            v, why = res[u]
            if v in ("hard", "unreach"):
                s = state.get(u, {})
                if s.get("kind") != v:
                    s = {"kind": v, "count": 0, "first": TODAY}
                if s.get("last") != TODAY:
                    s["count"] += 1
                s["last"], s["reason"] = TODAY, why
                new_state[u] = s
                need = STRIKES_UNREACH if v == "unreach" else (STRIKES_EMPTY if why in ("empty", "noconfigs") else STRIKES)
                if s["count"] >= need and not any(k in u for k in keep):
                    cands.append(u)
            elif v == "soft" and u in state:
                new_state[u] = state[u]
        if len(cands) > max(3, n * MAX_RATIO):
            notes.append(f"{len(cands)} links qualify for removal, above the safety limit "
                         f"({MAX_RATIO:.0%}). Nothing was removed; check the report.")
            cands = []

    removed = set(cands)
    new_lines = lines
    if removed:
        drop = {i for i, u in link_lines(lines) if u in removed}
        new_lines = [l for i, l in enumerate(lines) if i not in drop]
        new_lines, empty = drop_empty_blocks(new_lines)
        if empty:
            notes.append(f"{empty} code block(s) became empty and were removed from the README.")
        for u in removed:
            new_state.pop(u, None)

    new_lines, counted = update_counts(new_lines)
    new_lines, counted_r = update_repo_count(new_lines)
    if counted or counted_r:
        notes.append("Numbers in the README were refreshed (links per section, total, repositories).")

    dates = 0
    if (removed and UPDATE_DATE != "never") or UPDATE_DATE == "always":
        new_lines, dates = bump_dates(new_lines)
        if not dates:
            notes.append("No date line found to refresh (add <!--updated-->...<!--/updated--> to the README).")

    # ---- report
    rows = ["| status | link | detail |", "|---|---|---|"]
    for u in urls:
        v, why = res[u]
        if v == "ok":
            continue
        s = new_state.get(u, {})
        tag = "REMOVED" if u in removed else v
        prog = f"{s.get('count', 0)} day(s) in a row" if s else ""
        rows.append(f"| {tag} | {u} | {why} {prog} |")
    ok = sum(1 for v, _ in res.values() if v == "ok")
    report = [f"### Subscription health", f"{ok}/{n} links OK, {len(removed)} removed, "
              f"{'dates refreshed' if dates else 'dates unchanged'}", ""] + notes + [""] + rows
    text = "\n".join(report)
    print(text)
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        with open(p, "a", encoding="utf-8") as f:
            f.write(text + "\n")

    if DRY:
        print("DRY_RUN: no files written")
        return
    if "".join(new_lines) != raw:
        with open(README, "w", encoding="utf-8", newline="") as f:
            f.write("".join(new_lines))
    if new_state != state:
        os.makedirs(os.path.dirname(STATE) or ".", exist_ok=True)
        with open(STATE, "w", encoding="utf-8") as f:
            json.dump(new_state, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")


if __name__ == "__main__":
    main()
