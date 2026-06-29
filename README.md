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
aur-insight firefox-nightly          # review one package
aur-insight pkg-a pkg-b pkg-c        # review several
aur-insight --syu                    # review every pending AUR update (uses paru -Qua)
aur-insight --install foo            # review, then offer to run `paru -S foo`
aur-insight --dry-run foo            # show exactly what would be sent to the LLM, spend nothing
```

Exit code is `1` if anything came back **HIGH RISK**, `0` otherwise — handy for
scripts and hooks.

## Run automatically on every paru operation

Source the hook from your shell rc to make reviews happen on their own:

```bash
echo 'source /path/to/aur-insight/paru-hook.sh' >> ~/.bashrc   # or ~/.zshrc
```

Now `paru -S <pkg>` and `paru -Syu` print an aur-insight verdict **before**
paru's own confirmation prompt — you read the verdict, then paru asks you to
proceed as usual. Toggle it off any time with `export AUR_INSIGHT_OFF=1`.

## Privacy & scope

- Everything runs on your machine. The only outbound calls are to the public
  AUR (to fetch PKGBUILDs/metadata) and to the LLM endpoint **you** configure.
- v1 reviews PKGBUILDs, `.install` hooks, recent diffs, and AUR metadata. It
  does **not** do binary analysis, non-AUR packages, or hosted backends.
- **Ownership-transfer detection** works with no auth: aur-insight reads the
  package's commit history from the AUR's cgit atom feed and flags when the
  committing identity last changed — the classic supply-chain risk window.
- **Maintainer account age** requires a logged-in AUR session (the account
  page is auth-gated). Set `AUR_INSIGHT_COOKIE` to your AUR session cookie to
  enable it; otherwise aur-insight falls back to "how long this maintainer has
  been committing to this package." It never invents data it can't fetch.
- **What it does _not_ inspect yet:** the actual upstream source the PKGBUILD
  downloads (`source=`). A clean PKGBUILD that pulls a malicious tarball or git
  commit — the xz-utils pattern — is **not** caught by v1. Reviewing the
  payload (source-diff analysis for source packages, binary analysis for
  `-bin` packages) is the headline item on the roadmap, not a shipped feature.
  Don't read a LOW verdict as "the code is safe" — read it as "the packaging
  is clean."
- It's an assistant, not an authority. A clean verdict is not a guarantee, and
  the final call is always yours.

## License

MIT. See [LICENSE](LICENSE).
