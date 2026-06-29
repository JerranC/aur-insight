# aur-insight

**LLM-backed security review for AUR packages — before you install.**
_Powered by [Atlas Insight](https://atlasinsight.io)_

AUR package management on Arch is basically a part-time job: every install and
every `-Syu` is a small act of trust in a stranger's PKGBUILD. `aur-insight`
reads the PKGBUILD, the `.install` hooks, the most recent git diff, and the
AUR metadata for you, hands it all to an LLM with a security-focused prompt,
and prints a plain-English **LOW / MEDIUM / HIGH RISK** verdict.

It **never installs anything itself and never makes the decision for you.** It
tells you what it sees; you decide. Bring your own API key — your packages and
prompts go straight to the endpoint you configure, nowhere else.

```
aur-insight | analyzing screenconnect-bin...

VERDICT: LOW RISK ✓
Official vendor source, checksums present, hooks limited to standard tasks.

  ✓ Source pulls from the official ConnectWise domain
  ✓ sha256sums present and specific
  ✓ No unexpected package-manager calls in build or install
  ✓ Maintainer active; package not orphaned or freshly submitted
  ✓ .install hooks limited to systemctl and update-desktop-database

Powered by Atlas Insight | atlasinsight.io
```

## What it flags

- `npm` / `bun` / `pnpm` / `yarn` / `pip` / `cargo` / `curl` / `wget` pulling and
  running code at build or install time, especially for package types that
  don't justify it (e.g. a `-bin` package shelling out to npm)
- `curl … | bash` and other download-then-execute patterns
- `source=` URLs pointing somewhere other than the project's official domain —
  typosquats, pastebins, raw IPs, shortened links
- missing, `SKIP`, or zeroed checksums on remote sources
- `post_install` / `post_upgrade` hooks doing more than the usual housekeeping
- metadata smells: orphaned package, freshly submitted, inconsistent history
- anything structurally wrong for the declared package type

It is deliberately proportionate: a clean PKGBUILD from an official source gets
told it's fine. No fear-mongering.

## Install

```bash
git clone https://github.com/<you>/aur-insight.git
cd aur-insight
./setup.sh
```

`setup.sh` installs the CLI to `~/.local/bin`, prompts you for a provider,
model slug, and key (stored `0600`), and optionally wires up the paru hook.
Requires Python 3.6+ and nothing else — standard library only, one file.

Prefer to do it by hand? It's just:

```bash
install -Dm755 aur_insight.py ~/.local/bin/aur-insight
mkdir -p ~/.config/aur-insight && cp config.example ~/.config/aur-insight/config
$EDITOR ~/.config/aur-insight/config
```

## Configure (bring your own key)

`setup.sh` writes the config for you; to edit it later it lives at
`~/.config/aur-insight/config`.

Any OpenAI-compatible `/chat/completions` endpoint works:

| Provider  | `endpoint`                        | example `model`              |
|-----------|-----------------------------------|------------------------------|
| OpenAI    | `https://api.openai.com/v1`       | `gpt-4o-mini`                |
| Anthropic | `https://api.anthropic.com/v1`    | `claude-haiku-4-5-20251001`  |
| Ollama    | `http://localhost:11434/v1`       | `llama3.1` (fully local)     |

Environment variables override the file, so CI and one-off keys are easy:

```bash
export AUR_INSIGHT_API_KEY=sk-...
export AUR_INSIGHT_ENDPOINT=https://api.openai.com/v1
export AUR_INSIGHT_MODEL=gpt-4o-mini
```

`OPENAI_API_KEY` is honored as a fallback.

## Use

```bash
aur-insight firefox-nightly          # review one package's packaging
aur-insight pkg-a pkg-b pkg-c        # review several
aur-insight --syu                    # review every pending AUR update (uses paru -Qua)
aur-insight --deep firefox-nightly   # ALSO download and review the upstream source payload
aur-insight --diff --syu             # for updates: review ONLY what changed since installed
aur-insight --install foo            # review, then offer to run `paru -S foo`
aur-insight --dry-run foo            # show exactly what would be sent to the LLM, spend nothing
aur-insight --no-cache foo           # ignore the cached verdict and re-analyze
```

Exit code is `1` if anything came back **HIGH RISK**, `0` otherwise — handy for
scripts and hooks.

### Three depths of review

| Mode       | Reads                                                              | Catches                                              |
|------------|-------------------------------------------------------------------|-----------------------------------------------------|
| default    | PKGBUILD, `.install` hooks, repo files (patches), metadata        | malicious **packaging** — bad maintainer, evil hooks |
| `--deep`   | all of the above **+ the real `source=` payload's build/install scripts** | malicious **code** in a clean-looking package (xz pattern) |
| `--diff`   | the **delta** since your installed version — packaging diff **+ source build-script diff** | a package that was clean last version and **turned malicious in an update** |

`--deep` downloads each source, reads it **in memory** (no extraction to disk,
so a hostile archive can't traverse paths), and samples the files that actually
execute at build/install time — `configure`, `Makefile`, `*.sh`, `setup.py`,
`package.json`, `build.rs`, and friends — where supply-chain backdoors hide.
It's bounded hard: a 30 MB download cap, 25 files, ~45 KB of code to the model.
Archives stdlib can't open (e.g. `.zst`) and `hg`/`svn`/`bzr` sources are
skipped with a note rather than silently ignored.

`--diff` is the update-aware mode. It figures out the version you already have
(`pacman -Q`, or paru's update list), pulls the **packaging diff** between the
two AUR commits and the **build-script diff** between the two source payloads,
and asks the model to focus on what changed — because a previously-trusted
package quietly growing a malicious build step is the realistic attack. On a
**fresh** install there's nothing to diff against, so `--diff` automatically
falls back to a full `--deep` review. This is what the paru hook uses by default.

### Caching

Verdicts are cached under `~/.cache/aur-insight/`, keyed by the **exact**
input (endpoint + model + every artifact). A new package version changes the
PKGBUILD/diff/source, so it misses and re-analyzes; a repeated `-Syu` over
unchanged packages is instant and free. `--no-cache` forces a fresh call.

## Run automatically on every paru operation

Source the hook from your shell rc to make reviews happen on their own:

```bash
echo 'source /path/to/aur-insight/paru-hook.sh' >> ~/.bashrc   # or ~/.zshrc
```

Now `paru -S <pkg>` and `paru -Syu` print an aur-insight verdict **before**
paru's own confirmation prompt — you read the verdict, then paru asks you to
proceed as usual. The hook runs in `--diff` mode: updates are reviewed as a
diff, fresh installs as a full `--deep` payload review.

- `export AUR_INSIGHT_OFF=1` — temporarily disable the hook.
- `export AUR_INSIGHT_DEEP=1` — review the **full** payload every time instead
  of just the diff (slower, more tokens, more thorough).

## Privacy & scope

- Everything runs on your machine. The only outbound calls are to the public
  AUR (to fetch PKGBUILDs/metadata) and to the LLM endpoint **you** configure.
- Reviews packaging (PKGBUILD, `.install`, repo files, metadata), and with
  `--deep`/`--diff` the upstream source build scripts. It does **not** do binary
  analysis, non-AUR packages, or hosted backends.
- **Ownership-transfer detection** works with no auth: aur-insight reads the
  package's commit history from the AUR's cgit atom feed and flags when the
  committing identity last changed — the classic supply-chain risk window.
- **Maintainer account age** requires a logged-in AUR session (the account
  page is auth-gated). Set `AUR_INSIGHT_COOKIE` to your AUR session cookie to
  enable it; otherwise aur-insight falls back to "how long this maintainer has
  been committing to this package." It never invents data it can't fetch.
- **Source payload:** `--deep` reviews the build/install-time scripts inside
  the actual `source=` download — that's the fix for "clean PKGBUILD, malicious
  code." It is **not** exhaustive: it samples build-relevant text files within
  hard caps, so a backdoor buried in compiled output, a `.zst` archive, or a
  giant source tree can still slip past. A clean `--deep` verdict means "nothing
  obviously wrong in the packaging or the build scripts we sampled," not "this
  code is proven safe."
- **Version diffing** (`--diff`) reviews the delta between your installed
  version and the update — the strongest check for "was this quietly backdoored
  in an update?" It diffs build scripts, not every source file, and only works
  when the source URL carries the version (so the old payload is reconstructable).
- **Still out of scope:** binary analysis of `-bin` packages and non-AUR
  packages.
- It's an assistant, not an authority. A clean verdict is not a guarantee, and
  the final call is always yours.

## License

MIT. See [LICENSE](LICENSE).
