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
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

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

CACHE_DIR = os.path.expanduser("~/.cache/aur-insight")

# --- deep (source-payload) analysis limits --------------------------------
# Downloading attacker-controlled archives demands hard bounds: a capped
# download, a capped number of extracted files, and per-file/total char caps
# on what reaches the model. We never write archive members to disk by name
# (no zip-slip); everything is read in memory.
MAX_DOWNLOAD_BYTES = 30 * 1024 * 1024      # refuse sources larger than this
MAX_DEEP_FILES = 25                         # most build files we'll sample
MAX_DEEP_FILE_CHARS = 4000                  # per-file cap sent to the model
MAX_DEEP_TOTAL_CHARS = 45000                # total deep payload cap

# Files that actually execute at build/install time — where a backdoor hides
# in plain sight (the xz-utils pattern lived in build/test scripts, not the C).
BUILD_FILE_NAMES = (
    "configure", "configure.ac", "configure.in", "makefile", "makefile.am",
    "makefile.in", "cmakelists.txt", "meson.build", "build.rs", "setup.py",
    "setup.cfg", "pyproject.toml", "package.json", "wscript", "build.sh",
    "install.sh", "postinstall.js", "preinstall.js", "gradlew", "build.gradle",
    "build.ninja", "snapcraft.yaml", ".pc",
)
BUILD_FILE_SUFFIXES = (".sh", ".bash", ".m4", ".mk", ".cmake", ".pre", ".post")

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
- if an "UPSTREAM SOURCE: build/install-time files" section is present, it \
contains real code from the package's source= payload (not the packaging). \
Review it for backdoors, obfuscated or base64/hex-encoded blobs, code that \
phones home, or anything that does not belong in a build script — this is \
where supply-chain backdoors like xz-utils hide. If that section is ABSENT, \
do not assume the payload is safe; make clear you reviewed only the packaging.
- if you are shown "CHANGES SINCE <version>" sections, the user already ran \
the previous version and is updating. Focus on the delta: flag newly added \
network calls, package-manager invocations, download-and-execute steps, \
obfuscation, or new install hooks even when small — a previously-trusted \
package turning malicious in an update is the central supply-chain risk. \
Unchanged, boring diffs are reassuring; say so.

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
# Verdict cache — keyed by the exact input, so a new package version (new
# PKGBUILD/diff/source) misses and re-analyzes, but a repeated -Syu is free.
# ---------------------------------------------------------------------------

def cache_key(cfg, message):
    blob = "{0}\n{1}\n{2}".format(cfg["endpoint"], cfg["model"], message)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def cache_get(key):
    try:
        with open(os.path.join(CACHE_DIR, key + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def cache_put(key, result):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(os.path.join(CACHE_DIR, key + ".json"), "w",
                  encoding="utf-8") as f:
            json.dump(result, f)
    except OSError:
        pass


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


def pkgbuild_vars(pkgbuild, pkgbase, meta):
    """Best-effort map of the variables that show up in source= entries."""
    vmap = {"pkgbase": pkgbase}
    pm = re.search(r"^\s*pkgname\s*=\s*([^\s#()]+)", pkgbuild, re.M)
    if pm:
        vmap["pkgname"] = pm.group(1).strip("'\"")
    pv = re.search(r"^\s*pkgver\s*=\s*([^\s#]+)", pkgbuild, re.M)
    if pv:
        vmap["pkgver"] = pv.group(1).strip("'\"")
    elif meta.get("Version"):
        vmap["pkgver"] = str(meta["Version"]).rsplit("-", 1)[0]
    # Capture simple `_foo=bar` custom vars (common: _gitcommit, _pkgver).
    for m in re.finditer(r"^\s*(_[\w]+)\s*=\s*([^\s#()]+)", pkgbuild, re.M):
        vmap[m.group(1)] = m.group(2).strip("'\"")
    return vmap


def expand_vars(token, vmap):
    """Resolve $var / ${var} and the common bash substitutions ${var//a/b}
    (replace all) and ${var/a/b} (replace first) seen in source= URLs."""
    def repl(m):
        expr = m.group(1)
        sub = re.match(r"(\w+)//(.*?)/(.*)$", expr)
        if sub and vmap.get(sub.group(1)):
            return vmap[sub.group(1)].replace(sub.group(2), sub.group(3))
        sub = re.match(r"(\w+)/(.*?)/(.*)$", expr)
        if sub and vmap.get(sub.group(1)):
            return vmap[sub.group(1)].replace(sub.group(2), sub.group(3), 1)
        return vmap.get(expr, m.group(0))

    token = re.sub(r"\$\{([^}]+)\}", repl, token)
    for var, val in vmap.items():
        if val:
            token = token.replace("$" + var, val)
    return token


def parse_sources(pkgbuild, vmap):
    """Parse every source=/source_arch=() entry into classified records:
    {raw, name, url, local, vcs, frag, resolved}. `url` is set for remote
    sources, `local` for files shipped in the AUR repo."""
    entries = []
    for m in re.finditer(r"^\s*source(?:_\w+)?\s*=\s*\((.*?)\)",
                         pkgbuild, re.S | re.M):
        for tok in re.findall(r"'([^']*)'|\"([^\"]*)\"|(\S+)", m.group(1)):
            raw = (tok[0] or tok[1] or tok[2]).strip()
            if raw:
                entries.append(_classify_source(raw, vmap))
    return entries


def _classify_source(raw, vmap):
    name, spec = None, raw
    if "::" in spec:
        name, spec = spec.split("::", 1)
    frag = ""
    if "#" in spec:
        spec, frag = spec.split("#", 1)
    vcs = None
    for proto in ("git+", "hg+", "svn+", "bzr+"):
        if spec.startswith(proto):
            vcs, spec = proto[:-1], spec[len(proto):]
            break
    resolved = expand_vars(spec, vmap)
    is_remote = bool(vcs) or re.match(r"(https?|ftp|git)://", resolved)
    return {
        "raw": raw, "name": name and expand_vars(name, vmap),
        "template": spec,  # unexpanded, so we can re-resolve for another version
        "url": resolved if is_remote else None,
        "local": None if is_remote else resolved,
        "vcs": vcs, "frag": expand_vars(frag, vmap),
        "unresolved": "$" in resolved,
    }


# ---------------------------------------------------------------------------
# Deep (source-payload) analysis — the actual upstream code, not just packaging
# ---------------------------------------------------------------------------

def _is_build_file(path):
    """True for files that execute during build/install — the real hiding
    place for supply-chain payloads (xz-utils lived in build/test scripts)."""
    base = path.rsplit("/", 1)[-1].lower()
    return base in BUILD_FILE_NAMES or base.endswith(BUILD_FILE_SUFFIXES)


def _looks_text(blob):
    return b"\x00" not in blob[:4096]


def _download_capped(url):
    """Download up to MAX_DOWNLOAD_BYTES; refuse (None) anything larger so a
    decompression-bomb or giant blob can't run us out of memory."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            blob = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except Exception:
        return None
    return None if len(blob) > MAX_DOWNLOAD_BYTES else blob


def _read_archive(blob):
    """Read regular files out of a tar (gz/bz2/xz) or zip archive entirely in
    memory. Never writes to disk, so archive member names can't traverse paths.
    Returns [(path, bytes)]; empty for formats stdlib can't open (e.g. .zst)."""
    out = []
    cap = MAX_DEEP_FILE_CHARS * 6
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        for m in tf.getmembers():
            if m.isfile() and m.size <= cap * 4:
                fh = tf.extractfile(m)
                if fh:
                    out.append((m.name, fh.read(cap)))
            if len(out) > 3000:
                break
        return out
    except (tarfile.TarError, EOFError, OSError):
        pass
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        for info in zf.infolist():
            if not info.is_dir() and info.file_size <= cap * 4:
                with zf.open(info) as fh:
                    out.append((info.filename, fh.read(cap)))
            if len(out) > 3000:
                break
    except (zipfile.BadZipFile, OSError):
        pass
    return out


def _git_sample(url, frag):
    """Shallow-clone a git source into a temp dir, read its files, clean up.
    Returns ([(path, bytes)], error_or_None)."""
    if not shutil.which("git"):
        return [], "git not installed (needed for git+ sources)"
    tmp = tempfile.mkdtemp(prefix="aur-insight-")
    try:
        cmd = ["git", "clone", "--depth", "1", "--quiet"]
        m = re.match(r"(tag|branch)=(.+)", frag or "")
        if m:
            cmd += ["--branch", m.group(2)]
        cmd += [url, tmp]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=120)
        except subprocess.SubprocessError:
            return [], "clone timed out"
        if r.returncode != 0:
            return [], "clone failed"
        files, cap = [], MAX_DEEP_FILE_CHARS * 6
        for root, dirs, names in os.walk(tmp):
            if ".git" in dirs:
                dirs.remove(".git")
            for fn in names:
                path = os.path.join(root, fn)
                try:
                    if os.path.getsize(path) > cap * 4:
                        continue
                    with open(path, "rb") as fh:
                        files.append((os.path.relpath(path, tmp), fh.read(cap)))
                except OSError:
                    continue
        return files, None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def deep_source_analysis(pkgbuild, pkgbase, meta):
    """Fetch the real upstream source the PKGBUILD downloads and sample the
    build-time-executed files for the model. Returns (artifact, notes, count).
    This is what lets aur-insight reason about a clean PKGBUILD that pulls in
    malicious code — but it costs bandwidth and tokens, so it's opt-in."""
    vmap = pkgbuild_vars(pkgbuild, pkgbase, meta)
    candidates, notes = [], []
    for s in parse_sources(pkgbuild, vmap):
        if not s["url"]:
            continue  # local files are already included as repo extras
        label = s["name"] or s["url"].rsplit("/", 1)[-1] or s["url"]
        if s["unresolved"]:
            notes.append("unresolved source URL, skipped: " + s["raw"])
            continue
        if s["vcs"] == "git":
            files, err = _git_sample(s["url"], s["frag"])
            if s["frag"].startswith("commit="):
                notes.append("{0}: pinned to {1}; shallow clone is HEAD, may "
                             "differ".format(label, s["frag"]))
        elif s["vcs"]:
            files, err = [], "{0} sources not supported in --deep".format(s["vcs"])
        else:
            blob = _download_capped(s["url"])
            if blob is None:
                files, err = [], "download failed or over {0}MB cap".format(
                    MAX_DOWNLOAD_BYTES // 1024 // 1024)
            else:
                files = _read_archive(blob)
                err = ("archive not readable by stdlib (e.g. .zst), skipped"
                       if not files else None)
        if err:
            notes.append("{0}: {1}".format(label, err))
        for path, blob in files:
            candidates.append((label, path, blob))

    picked, total = [], 0
    for label, path, blob in sorted(candidates, key=lambda c: c[1].count("/")):
        if len(picked) >= MAX_DEEP_FILES or total >= MAX_DEEP_TOTAL_CHARS:
            break
        if not _is_build_file(path) or not _looks_text(blob):
            continue
        text = blob.decode("utf-8", "replace")[:MAX_DEEP_FILE_CHARS]
        picked.append("--- {0} :: {1} ---\n{2}".format(label, path, text))
        total += len(text)
    return "\n\n".join(picked), notes, len(picked)


# ---------------------------------------------------------------------------
# Version diffing — what changed since the version you already trust
# ---------------------------------------------------------------------------

def packaging_version_diff(pkgbase, history, old_version):
    """Unified diff of PKGBUILD/.SRCINFO/etc. between the commit that set
    old_version and the newest commit, via cgit's plain patch-range endpoint.
    Falls back to the latest single patch if the old commit can't be pinned."""
    new_sha = history[0].get("sha") if history else None
    old_sha = None
    for c in history:
        if old_version and old_version in c.get("title", ""):
            old_sha = c.get("sha")
            break
    if new_sha and old_sha and new_sha != old_sha:
        diff = http_get("{0}/patch/?h={1}&id={2}&id2={3}".format(
            CGIT, urllib.parse.quote(pkgbase), new_sha, old_sha))
        return (diff, None) if diff else ("", "packaging diff range unavailable")
    latest = http_get("{0}/patch/?h={1}".format(CGIT, urllib.parse.quote(pkgbase)))
    return (latest or "",
            "old version not pinned in recent history; showing latest patch only")


def _build_files_map(blob):
    """{normalized_path: text} of build/install files in an archive, with the
    version-bearing top directory stripped so the two versions line up."""
    out = {}
    for path, data in _read_archive(blob):
        norm = path.split("/", 1)[1] if "/" in path else path
        if norm and _is_build_file(norm) and _looks_text(data):
            out[norm] = data.decode("utf-8", "replace")
    return out


def source_build_diff(pkgbuild, pkgbase, meta, old_version):
    """Download the old and new source payloads and diff their build/install
    scripts. The headline check: a package that was clean last version and
    grew a malicious build step in this one shows up right here."""
    new_vmap = pkgbuild_vars(pkgbuild, pkgbase, meta)
    old_vmap = dict(new_vmap, pkgver=old_version)
    chunks, notes, total = [], [], 0
    for s in parse_sources(pkgbuild, new_vmap):
        if not s["url"] or s["vcs"] or s["unresolved"]:
            continue
        label = s["name"] or s["url"].rsplit("/", 1)[-1]
        new_url = expand_vars(s["template"], new_vmap)
        old_url = expand_vars(s["template"], old_vmap)
        if old_url == new_url:
            notes.append("{0}: URL has no version component — can't isolate the "
                         "change (use --deep)".format(label))
            continue
        new_blob, old_blob = _download_capped(new_url), _download_capped(old_url)
        if not new_blob or not old_blob:
            notes.append("{0}: couldn't fetch both versions to diff".format(label))
            continue
        new_map, old_map = _build_files_map(new_blob), _build_files_map(old_blob)
        changed = 0
        for path in sorted(set(new_map) | set(old_map)):
            if total >= MAX_DEEP_TOTAL_CHARS:
                break
            old_lines = old_map.get(path, "").splitlines()
            new_lines = new_map.get(path, "").splitlines()
            if old_lines == new_lines:
                continue
            ud = list(difflib.unified_diff(
                old_lines, new_lines, fromfile="old/" + path,
                tofile="new/" + path, lineterm=""))
            text = "\n".join(ud[:400])[:MAX_DEEP_FILE_CHARS]
            chunks.append(text)
            total += len(text)
            changed += 1
        if not changed and (new_map or old_map):
            notes.append("{0}: build scripts unchanged between versions".format(label))
    return "\n\n".join(chunks), notes


def fetch_history(pkgbase):
    """Recent commits to the AUR packaging repo, newest first, from the cgit
    atom feed. Each entry is {author, date, title, sha}. Drives ownership-
    transfer detection and version diffing without an authenticated session."""
    raw = http_get("{0}/atom/?h={1}".format(CGIT, urllib.parse.quote(pkgbase)))
    if not raw:
        return []
    commits = []
    for entry in re.findall(r"<entry>(.*?)</entry>", raw, re.S):
        name = re.search(r"<name>(.*?)</name>", entry, re.S)
        date = re.search(r"<updated>(.*?)</updated>", entry, re.S)
        title = re.search(r"<title>(.*?)</title>", entry, re.S)
        sha = re.search(r"id=([a-f0-9]{40})", entry)
        if name and date:
            commits.append({
                "author": name.group(1).strip(),
                "date": date.group(1).strip(),
                "title": title.group(1).strip() if title else "",
                "sha": sha.group(1) if sha else None,
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


def gather(pkgname, deep=False, old_version=None):
    """Collect everything we know about a package. Returns a dict or None if
    the package doesn't exist on the AUR. If old_version is given and differs
    from the new version, produces targeted version diffs (packaging + source
    build scripts); otherwise deep=True downloads and samples the full payload."""
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

    # Local files shipped in the AUR repo (patches, .sh, .service...) are cheap
    # to fetch and high-signal — a malicious .patch is a classic vector.
    extras, vmap = {}, pkgbuild_vars(pkgbuild, pkgbase, meta)
    for s in parse_sources(pkgbuild, vmap):
        name = s["local"]
        if (name and name not in installs and "/" not in name
                and "$" not in name and len(extras) < 12):
            body = cgit_plain(pkgbase, name)
            if body and _looks_text(body.encode("utf-8", "replace")):
                extras[name] = body

    diff = http_get("{0}/patch/?h={1}".format(CGIT, urllib.parse.quote(pkgbase)))
    history = fetch_history(pkgbase)

    new_version = pkgbuild_vars(pkgbuild, pkgbase, meta).get("pkgver")
    do_diff = bool(old_version and new_version and old_version != new_version)

    ver_pkg_diff, ver_src_diff, ver_notes = "", "", []
    deep_artifact, deep_notes, deep_count = "", [], 0
    if do_diff:
        ver_pkg_diff, pnote = packaging_version_diff(pkgbase, history, old_version)
        ver_src_diff, ver_notes = source_build_diff(
            pkgbuild, pkgbase, meta, old_version)
        if pnote:
            ver_notes = [pnote] + ver_notes
    elif deep:
        deep_artifact, deep_notes, deep_count = deep_source_analysis(
            pkgbuild, pkgbase, meta)

    return {
        "name": pkgname,
        "pkgbase": pkgbase,
        "meta": meta,
        "pkgbuild": pkgbuild,
        "installs": installs,
        "extras": extras,
        "diff": diff or "",
        "history": history,
        "account_age": fetch_account_age(meta.get("Maintainer")),
        "deep_artifact": deep_artifact,
        "deep_notes": deep_notes,
        "deep_count": deep_count,
        "diff_against": old_version if do_diff else None,
        "ver_pkg_diff": ver_pkg_diff,
        "ver_src_diff": ver_src_diff,
        "ver_notes": ver_notes,
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

    for name, body in data.get("extras", {}).items():
        parts.append("\n== REPO FILE: {0} ==\n{1}".format(name, trim(body)))

    if data.get("diff_against"):
        old = data["diff_against"]
        parts.append("\n== PACKAGING CHANGES SINCE {0} ==\n{1}".format(
            old, trim(data.get("ver_pkg_diff") or "(no packaging changes)")))
        parts.append(
            "\n== SOURCE BUILD-SCRIPT CHANGES SINCE {0} ==\nDiff of build/"
            "install-time files in the actual source payload between the "
            "version installed and the new one. Scrutinize anything newly "
            "added.\n{1}".format(
                old, trim(data.get("ver_src_diff") or "(no build-script changes)")))
        for note in data.get("ver_notes", []):
            parts.append("note: " + note)
    elif is_update and data["diff"]:
        parts.append("\n== MOST RECENT PACKAGING DIFF ==\n" + trim(data["diff"]))

    if data.get("deep_artifact"):
        parts.append(
            "\n== UPSTREAM SOURCE: build/install-time files ({0} sampled) ==\n"
            "These are pulled from the actual source= payload, not the "
            "packaging. Scrutinize for backdoors, obfuscation, or network "
            "calls hidden in build scripts.\n{1}".format(
                data["deep_count"], data["deep_artifact"]))
    if data.get("deep_notes"):
        parts.append("\n== UPSTREAM SOURCE NOTES ==\n- "
                     + "\n- ".join(data["deep_notes"]))

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


def render(result, cached=False):
    color, label, mark = VERDICT_STYLE.get(result["verdict"],
                                           VERDICT_STYLE["UNKNOWN"])
    print()
    tag = "  {0}(cached){1}".format(C.DIM, C.RESET) if cached else ""
    print("{0}{1}VERDICT: {2} {3}{4}{5}".format(
        C.BOLD, color, label, mark, C.RESET, tag))
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

def analyze_one(cfg, pkgname, is_update=False, deep=False, old_version=None,
                use_cache=True):
    """Returns the verdict string, or None if the package wasn't analyzable."""
    banner("analyzing {0}{1}{2}...".format(C.BOLD, pkgname, C.RESET))
    data = gather(pkgname, deep=deep, old_version=old_version)
    if data is None:
        print("  {0}not found on the AUR — skipping (is it a repo package?)"
              "{1}".format(C.YELLOW, C.RESET))
        return None
    if not data["pkgbuild"]:
        print("  {0}could not fetch PKGBUILD — skipping{1}".format(
            C.YELLOW, C.RESET))
        return None

    if data.get("diff_against"):
        print("  {0}update {1} -> {2}; reviewing what changed{3}".format(
            C.DIM, data["diff_against"], data["meta"].get("Version", "?"), C.RESET))
    elif deep:
        print("  {0}reviewing upstream source payload (deep){1}".format(
            C.DIM, C.RESET))

    message = build_user_message(data, is_update)
    key = cache_key(cfg, message)
    result = cache_get(key) if use_cache else None
    cached = result is not None
    if result is None:
        try:
            content = analyze_with_llm(cfg, message)
        except Exception as exc:  # network / auth / endpoint errors
            die("LLM request failed: {0}".format(exc))
        result = parse_verdict(content)
        cache_put(key, result)
    render(result, cached=cached)
    return result["verdict"]


def _clean_pkgver(version):
    """Strip epoch and pkgrel: '1:12.0.2-3' -> '12.0.2' (matches source URLs)."""
    if ":" in version:
        version = version.split(":", 1)[1]
    return version.rsplit("-", 1)[0]


def pacman_version(pkgname):
    """Installed pkgver of a package, or None if not installed / no pacman."""
    try:
        out = subprocess.run(["pacman", "-Q", pkgname], capture_output=True,
                             text=True, timeout=30)
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    parts = out.stdout.split()
    return _clean_pkgver(parts[1]) if out.returncode == 0 and len(parts) > 1 else None


def pending_aur_updates():
    """AUR packages with pending updates as (name, old_version) pairs, parsed
    from `paru -Qua` lines like 'pkg 1.0-1 -> 1.1-1'."""
    try:
        out = subprocess.run(["paru", "-Qua"], capture_output=True,
                             text=True, timeout=120)
    except (FileNotFoundError, subprocess.SubprocessError):
        die("could not run `paru -Qua` — is paru installed and on PATH?")
    pairs = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if parts and not line.startswith(":"):
            old = _clean_pkgver(parts[1]) if len(parts) > 1 else None
            pairs.append((parts[0], old))
    return pairs


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
    parser.add_argument("--deep", action="store_true",
                        help="also download and review the upstream source "
                             "payload, not just the packaging (slower, more tokens)")
    parser.add_argument("--diff", action="store_true",
                        help="for updates, review only what changed since the "
                             "installed version (packaging + source build scripts); "
                             "falls back to --deep for fresh installs")
    parser.add_argument("--no-cache", action="store_true",
                        help="ignore any cached verdict and re-analyze")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be sent to the LLM, then stop")
    args = parser.parse_args(argv)

    # --diff implies a deep fallback: if there's no installed version to diff
    # against (a fresh install), review the full payload instead.
    deep = args.deep or args.diff

    # Resolve targets to (name, old_version) — old_version drives diff mode.
    if args.syu:
        pairs = pending_aur_updates()
        is_update = True
    else:
        if not args.packages and not args.dry_run:
            parser.print_help()
            return 2
        is_update = args.update or args.diff
        olds = ({p: pacman_version(p) for p in args.packages}
                if args.diff else {})
        pairs = [(p, olds.get(p)) for p in args.packages]

    if args.dry_run:
        for pkg, old in pairs:
            data = gather(pkg, deep=deep, old_version=old if args.diff else None)
            if data is None:
                print("# {0}: not on the AUR".format(pkg))
                continue
            print("# ===== {0} =====".format(pkg))
            print(build_user_message(data, is_update))
            print()
        return 0

    cfg = load_config()
    if not cfg["api_key"]:
        die("no API key configured. Set AUR_INSIGHT_API_KEY (or OPENAI_API_KEY) "
            "or add `api_key = ...` to ~/.config/aur-insight/config")

    if args.syu and not pairs:
        banner("no pending AUR updates to analyze.")
        return 0
    if args.syu:
        banner("{0} AUR update(s) to review: {1}".format(
            len(pairs), ", ".join(n for n, _ in pairs)))

    targets = [n for n, _ in pairs]
    verdicts = {}
    for pkg, old in pairs:
        verdicts[pkg] = analyze_one(
            cfg, pkg, is_update=is_update, deep=deep,
            old_version=old if args.diff else None, use_cache=not args.no_cache)
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
