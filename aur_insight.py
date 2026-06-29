#!/usr/bin/env python3
"""
aur-insight — LLM-backed security review for AUR packages.
Powered by Atlas Insight

Fetches a package's PKGBUILD, .install hooks, recent git diff, and AUR
metadata, then asks a configured LLM for a GREEN / YELLOW / RED verdict
before you install. It never installs anything on its own and never makes
the final call for you — it tells you what it sees and you decide.

Single file, standard library only. Bring your own OpenAI-compatible API key.
MIT licensed.
"""

import argparse
import calendar
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUR = "https://aur.archlinux.org"
RPC = AUR + "/rpc/v5/info"
CGIT = AUR + "/cgit/aur.git"
USER_AGENT = "aur-insight/1.0 (+https://atlasinsight.io)"
HTTP_TIMEOUT = 15

CONFIG_PATHS = [
    os.path.expanduser("~/.config/aur-insight/config"),
    os.path.expanduser("~/.aur-insight"),
]

# Cap the size of any single artifact we send to the model. PKGBUILDs are
# tiny; a malicious diff could be huge, so we trim to stay cheap and bounded.
MAX_ARTIFACT_CHARS = 12000

SYSTEM_PROMPT = """\
You are a security reviewer for Arch Linux AUR packages. You are given the \
PKGBUILD, any .install hook files, a recent git diff, and AUR metadata for a \
single package. Decide how risky it is to install, as if a careful Arch user \
were about to run it on their machine.

Reason about, and flag, things like:
- npm / bun / pnpm / yarn / pip / cargo / curl / wget invocations inside the \
PKGBUILD or .install hooks that pull and execute code at build or install \
time, especially when the package type does not justify them (e.g. a binary \
package shelling out to npm).
- curl/wget piped directly into bash/sh, or any "download then immediately \
execute" pattern.
- source= URLs that point somewhere other than the project's official domain, \
its real GitHub/GitLab releases, or a recognized mirror — typosquats, random \
file hosts, pastebins, IP addresses, shortened URLs.
- sha256sums (or other checksums) that are missing, set to 'SKIP', or zeroed \
out, particularly for remote sources.
- post_install / post_upgrade / pre_install hooks that do more than the usual \
(systemctl daemon-reload, update-desktop-database, gtk-update-icon-cache, \
ldconfig, etc.) — adding users, writing to /etc beyond the package's scope, \
opening network connections, modifying other packages, fetching code.
- metadata smells: orphaned package (no maintainer), very recently first \
submitted, or modified in a way inconsistent with an established package.
- anything structurally wrong for the declared package type.

Be proportionate. Most packages are fine; do not invent danger. A clean, \
boring PKGBUILD from an official source with present checksums is LOW risk and \
you should say so plainly.

Respond with ONLY a JSON object, no prose around it, in exactly this shape:
{
  "verdict": "LOW" | "MEDIUM" | "HIGH",
  "summary": "<one short sentence>",
  "findings": [
    {"level": "ok" | "warn" | "bad", "text": "<plain-English point>"}
  ]
}
Use "ok" for reassuring findings, "warn" for things worth a human glance, \
"bad" for genuine red flags. Order findings most-important first. Keep each \
finding to one line."""


# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------

class C:
    USE = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m" if USE else ""
    BOLD = "\033[1m" if USE else ""
    DIM = "\033[2m" if USE else ""
    GREEN = "\033[32m" if USE else ""
    YELLOW = "\033[33m" if USE else ""
    RED = "\033[31m" if USE else ""
    CYAN = "\033[36m" if USE else ""


def banner(text):
    print("{0}{1}aur-insight{2} | {3}".format(C.BOLD, C.CYAN, C.RESET, text))


def die(msg, code=1):
    print("{0}aur-insight: {1}{2}".format(C.RED, msg, C.RESET), file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config():
    """Env vars win over the config file. Returns a dict with api_key,
    endpoint, model. Accepts plain `key = value` lines (# comments ok)."""
    cfg = {"api_key": "", "endpoint": "https://api.openai.com/v1",
           "model": "gpt-4o-mini"}

    for path in CONFIG_PATHS:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if key in cfg:
                    cfg[key] = val
        break

    cfg["api_key"] = (os.environ.get("AUR_INSIGHT_API_KEY")
                      or os.environ.get("OPENAI_API_KEY") or cfg["api_key"])
    cfg["endpoint"] = (os.environ.get("AUR_INSIGHT_ENDPOINT")
                       or cfg["endpoint"]).rstrip("/")
    cfg["model"] = os.environ.get("AUR_INSIGHT_MODEL") or cfg["model"]
    return cfg


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_get(url, extra_headers=None):
    """GET text, or None on any error (missing file, network hiccup)."""
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def days_since_iso(iso):
    """Whole days since an ISO-8601 UTC timestamp, or None if unparseable."""
    try:
        secs = calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))
        return (int(time.time()) - secs) // 86400
    except (ValueError, TypeError):
        return None


def http_post_json(url, payload, api_key):
    data = json.dumps(payload).encode("utf-8")
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
        headers["x-api-key"] = api_key  # some gateways look here instead
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# AUR data gathering
# ---------------------------------------------------------------------------

def cgit_plain(pkgbase, filename):
    url = "{0}/plain/{1}?h={2}".format(
        CGIT, urllib.parse.quote(filename), urllib.parse.quote(pkgbase))
    return http_get(url)


def fetch_metadata(pkgname):
    raw = http_get(RPC + "?arg[]=" + urllib.parse.quote(pkgname))
    if not raw:
        return None
    try:
        results = json.loads(raw).get("results", [])
    except ValueError:
        return None
    return results[0] if results else None


def find_install_files(pkgbuild, pkgbase):
    """Pull install-hook filenames out of a PKGBUILD: the `install=` field
    plus anything ending in .install. Resolves the common $pkgname/$pkgbase
    substitutions so packages like `install=$pkgname.install` are caught."""
    pkgname = ""
    pm = re.search(r"^\s*pkgname\s*=\s*([^\s#()]+)", pkgbuild, re.M)
    if pm:
        pkgname = pm.group(1).strip("'\"")

    def expand(token):
        for var, val in (("pkgname", pkgname), ("pkgbase", pkgbase)):
            if val:
                token = token.replace("${%s}" % var, val).replace("$" + var, val)
        return token.strip("'\"")

    names = set()
    for m in re.finditer(r"^\s*install\s*=\s*([^\s#]+)", pkgbuild, re.M):
        names.add(expand(m.group(1)))
    for m in re.finditer(r"([\w.+-]+\.install)", pkgbuild):
        names.add(m.group(1))
    return [n for n in names if n and "$" not in n]


def fetch_history(pkgbase):
    """Recent commits to the AUR packaging repo, newest first, from the cgit
    atom feed. Each entry is {author, date, title}. Drives ownership-transfer
    detection without needing an authenticated session."""
    raw = http_get("{0}/atom/?h={1}".format(CGIT, urllib.parse.quote(pkgbase)))
    if not raw:
        return []
    commits = []
    for entry in re.findall(r"<entry>(.*?)</entry>", raw, re.S):
        name = re.search(r"<name>(.*?)</name>", entry, re.S)
        date = re.search(r"<updated>(.*?)</updated>", entry, re.S)
        title = re.search(r"<title>(.*?)</title>", entry, re.S)
        if name and date:
            commits.append({
                "author": name.group(1).strip(),
                "date": date.group(1).strip(),
                "title": title.group(1).strip() if title else "",
            })
    return commits


def fetch_account_age(username):
    """True AUR registration date for a maintainer. The account page requires
    a logged-in session, so this only runs when AUR_INSIGHT_COOKIE is set.
    Experimental and best-effort: returns a 'YYYY-MM-DD' string or None.
    Layout-dependent — if the AUR changes its account page this may stop
    working, and that's fine; the tool degrades to commit-history signals."""
    cookie = os.environ.get("AUR_INSIGHT_COOKIE")
    if not username or not cookie:
        return None
    html = http_get(AUR + "/account/" + urllib.parse.quote(username),
                    extra_headers={"Cookie": cookie})
    if not html:
        return None
    m = re.search(r"Registered[^0-9]*(\d{4}-\d{2}-\d{2})", html)
    return m.group(1) if m else None


def gather(pkgname):
    """Collect everything we know about a package. Returns a dict or None
    if the package doesn't exist on the AUR."""
    meta = fetch_metadata(pkgname)
    if meta is None:
        return None
    pkgbase = meta.get("PackageBase", pkgname)

    pkgbuild = cgit_plain(pkgbase, "PKGBUILD") or ""
    installs = {}
    for name in find_install_files(pkgbuild, pkgbase):
        body = cgit_plain(pkgbase, name)
        if body:
            installs[name] = body

    diff = http_get("{0}/patch/?h={1}".format(
        CGIT, urllib.parse.quote(pkgbase)))

    return {
        "name": pkgname,
        "pkgbase": pkgbase,
        "meta": meta,
        "pkgbuild": pkgbuild,
        "installs": installs,
        "diff": diff or "",
        "history": fetch_history(pkgbase),
        "account_age": fetch_account_age(meta.get("Maintainer")),
    }


def trim(text):
    if len(text) > MAX_ARTIFACT_CHARS:
        return text[:MAX_ARTIFACT_CHARS] + "\n...[truncated by aur-insight]..."
    return text


def ownership_lines(maintainer, history):
    """Turn recent commit history into ownership-transfer signal. Detects when
    the committing identity last changed — a strong proxy for the package
    changing hands, which is a classic supply-chain risk window."""
    if not history:
        return ["Recent commit history: unavailable"]
    authors = [c["author"] for c in history]
    current = authors[0]
    distinct = []
    for a in authors:
        if a not in distinct:
            distinct.append(a)

    lines = []
    if len(distinct) == 1:
        oldest = history[-1]["date"]
        span = days_since_iso(oldest)
        span_txt = " (~{0}+ days of consistent history)".format(span) if span else ""
        lines.append("Committer history: all {0} recent commits by '{1}'{2}".format(
            len(history), current, span_txt))
    else:
        idx = next((i for i, a in enumerate(authors) if a != current), None)
        if idx:  # current author held the top `idx` commits
            took_over = days_since_iso(history[idx - 1]["date"])
            when = "~{0} days ago".format(took_over) if took_over is not None else "recently"
            lines.append(
                "POSSIBLE OWNERSHIP TRANSFER: current committer '{0}' took over "
                "{1} (previously '{2}')".format(current, when, authors[idx]))
        lines.append("Distinct recent committers: " + ", ".join(distinct))
    return lines


def metadata_summary(meta, history=None, account_age=None):
    """Flatten the metadata we actually trust into lines the model can reason
    over. We surface only data we genuinely fetched — never invented."""
    now = int(time.time())
    lines = []
    maintainer = meta.get("Maintainer")
    lines.append("Maintainer: " + (maintainer or "NONE (package is ORPHANED)"))

    if account_age:
        age_days = days_since_iso(account_age + "T00:00:00Z")
        extra = " ({0} days ago)".format(age_days) if age_days is not None else ""
        lines.append("Maintainer AUR account registered: {0}{1}".format(
            account_age, extra))

    first = meta.get("FirstSubmitted")
    if first:
        lines.append("Package first submitted: {0} days ago".format(
            (now - first) // 86400))
    last = meta.get("LastModified")
    if last:
        lines.append("Last modified: {0} days ago".format((now - last) // 86400))

    if meta.get("OutOfDate"):
        lines.append("Flagged out-of-date: yes")
    lines.append("Votes: {0}, Popularity: {1}".format(
        meta.get("NumVotes", 0), round(meta.get("Popularity", 0) or 0, 3)))
    if meta.get("Version"):
        lines.append("Version: " + str(meta["Version"]))

    lines.extend(ownership_lines(maintainer, history or []))
    # Note: when AUR_INSIGHT_COOKIE is unset, true account age is unavailable
    # (the AUR account page requires login) and we rely on commit history above.
    return "\n".join(lines)


def build_user_message(data, is_update):
    parts = ["Package: {0} (pkgbase: {1})".format(data["name"], data["pkgbase"])]
    parts.append("\n== AUR METADATA ==\n" + metadata_summary(
        data["meta"], data.get("history"), data.get("account_age")))
    parts.append("\n== PKGBUILD ==\n" + trim(data["pkgbuild"] or "(empty)"))

    if data["installs"]:
        for name, body in data["installs"].items():
            parts.append("\n== INSTALL HOOK: {0} ==\n{1}".format(name, trim(body)))
    else:
        parts.append("\n== INSTALL HOOKS ==\n(none)")

    if is_update and data["diff"]:
        parts.append("\n== MOST RECENT GIT DIFF ==\n" + trim(data["diff"]))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM call + verdict parsing
# ---------------------------------------------------------------------------

def analyze_with_llm(cfg, user_message):
    payload = {
        "model": cfg["model"],
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }
    resp = http_post_json(cfg["endpoint"] + "/chat/completions",
                          payload, cfg["api_key"])
    try:
        content = resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError("unexpected response from endpoint: "
                           + json.dumps(resp)[:300])
    return content


def parse_verdict(content):
    """Pull the JSON verdict out of the model's reply, tolerating code fences
    or stray text. Returns a normalized dict."""
    match = re.search(r"\{.*\}", content, re.S)
    if not match:
        return {"verdict": "UNKNOWN", "summary": content.strip()[:200],
                "findings": []}
    try:
        obj = json.loads(match.group(0))
    except ValueError:
        return {"verdict": "UNKNOWN", "summary": content.strip()[:200],
                "findings": []}
    verdict = str(obj.get("verdict", "UNKNOWN")).upper()
    if verdict not in ("LOW", "MEDIUM", "HIGH"):
        verdict = "UNKNOWN"
    findings = []
    for f in obj.get("findings", []) or []:
        if isinstance(f, dict):
            findings.append({"level": str(f.get("level", "warn")).lower(),
                             "text": str(f.get("text", "")).strip()})
        else:
            findings.append({"level": "warn", "text": str(f).strip()})
    return {"verdict": verdict, "summary": str(obj.get("summary", "")).strip(),
            "findings": findings}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

VERDICT_STYLE = {
    "LOW": (C.GREEN, "LOW RISK", "✓"),
    "MEDIUM": (C.YELLOW, "MEDIUM RISK", "▲"),
    "HIGH": (C.RED, "HIGH RISK", "✗"),
    "UNKNOWN": (C.DIM, "UNKNOWN", "?"),
}
FINDING_MARK = {
    "ok": (C.GREEN, "✓"),
    "warn": (C.YELLOW, "▲"),
    "bad": (C.RED, "✗"),
}


def render(result):
    color, label, mark = VERDICT_STYLE.get(result["verdict"],
                                           VERDICT_STYLE["UNKNOWN"])
    print()
    print("{0}{1}VERDICT: {2} {3}{4}".format(
        C.BOLD, color, label, mark, C.RESET))
    if result["summary"]:
        print("{0}{1}{2}".format(C.DIM, result["summary"], C.RESET))
    print()
    for f in result["findings"]:
        fc, fmark = FINDING_MARK.get(f["level"], (C.DIM, "-"))
        print("  {0}{1}{2} {3}".format(fc, fmark, C.RESET, f["text"]))
    print()
    print("{0}Powered by Atlas Insight | atlasinsight.io{1}".format(
        C.DIM, C.RESET))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_one(cfg, pkgname, is_update=False):
    """Returns the verdict string, or None if the package wasn't analyzable."""
    banner("analyzing {0}{1}{2}...".format(C.BOLD, pkgname, C.RESET))
    data = gather(pkgname)
    if data is None:
        print("  {0}not found on the AUR — skipping (is it a repo package?)"
              "{1}".format(C.YELLOW, C.RESET))
        return None
    if not data["pkgbuild"]:
        print("  {0}could not fetch PKGBUILD — skipping{1}".format(
            C.YELLOW, C.RESET))
        return None

    message = build_user_message(data, is_update)
    try:
        content = analyze_with_llm(cfg, message)
    except Exception as exc:  # network / auth / endpoint errors
        die("LLM request failed: {0}".format(exc))
    result = parse_verdict(content)
    render(result)
    return result["verdict"]


def pending_aur_updates():
    """Ask paru for the list of AUR packages with pending updates."""
    try:
        out = subprocess.run(["paru", "-Qua"], capture_output=True,
                             text=True, timeout=120)
    except (FileNotFoundError, subprocess.SubprocessError):
        die("could not run `paru -Qua` — is paru installed and on PATH?")
    names = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(":"):
            names.append(line.split()[0])
    return names


def confirm(prompt):
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="aur-insight",
        description="LLM security review for AUR packages, before you install.")
    parser.add_argument("packages", nargs="*",
                        help="package name(s) to analyze")
    parser.add_argument("--syu", action="store_true",
                        help="analyze every AUR package with a pending update")
    parser.add_argument("--update", action="store_true",
                        help="treat targets as updates (include recent git diff)")
    parser.add_argument("--install", action="store_true",
                        help="after analysis, offer to run `paru -S <pkg>`")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be sent to the LLM, then stop")
    args = parser.parse_args(argv)

    if args.dry_run:
        for pkg in (pending_aur_updates() if args.syu else args.packages):
            data = gather(pkg)
            if data is None:
                print("# {0}: not on the AUR".format(pkg))
                continue
            print("# ===== {0} =====".format(pkg))
            print(build_user_message(data, args.syu or args.update))
            print()
        return 0

    cfg = load_config()
    if not cfg["api_key"]:
        die("no API key configured. Set AUR_INSIGHT_API_KEY (or OPENAI_API_KEY) "
            "or add `api_key = ...` to ~/.config/aur-insight/config")

    if args.syu:
        targets = pending_aur_updates()
        if not targets:
            banner("no pending AUR updates to analyze.")
            return 0
        banner("{0} AUR update(s) to review: {1}".format(
            len(targets), ", ".join(targets)))
        is_update = True
    else:
        targets = args.packages
        is_update = args.update
        if not targets:
            parser.print_help()
            return 2

    verdicts = {}
    for pkg in targets:
        verdicts[pkg] = analyze_one(cfg, pkg, is_update=is_update)
        print()

    if args.install and targets:
        worst = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            verdicts.get(targets[0]), 0)
        note = " (flagged HIGH RISK)" if worst == 3 else ""
        if confirm("Proceed with `paru -S {0}`{1}? [y/N] ".format(
                " ".join(targets), note)):
            os.execvp("paru", ["paru", "-S"] + list(targets))
        else:
            banner("aborted. Nothing was installed.")

    # Exit non-zero if anything came back HIGH, so hooks/scripts can react.
    return 1 if "HIGH" in verdicts.values() else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
