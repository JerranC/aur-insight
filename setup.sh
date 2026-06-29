#!/usr/bin/env bash
# aur-insight installer — clone the repo, run ./setup.sh, answer the prompts.
# Installs the CLI, writes your config (key stays local, chmod 600), and can
# wire up the automatic paru hook. Re-running is safe; it updates in place.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${AUR_INSIGHT_BIN_DIR:-$HOME/.local/bin}"
CONFIG_DIR="$HOME/.config/aur-insight"
CONFIG_FILE="$CONFIG_DIR/config"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/aur-insight"
HOOK_FILE="$DATA_DIR/paru-hook.sh"

c_bold=$'\033[1m'; c_cyan=$'\033[36m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
say() { printf '%saur-insight%s | %s\n' "$c_cyan$c_bold" "$c_off" "$1"; }

command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required but not found on PATH." >&2; exit 1; }

say "installing the CLI to ${c_bold}${BIN_DIR}/aur-insight${c_off}"
mkdir -p "$BIN_DIR"
install -m 755 "$REPO_DIR/aur_insight.py" "$BIN_DIR/aur-insight"
mkdir -p "$DATA_DIR"
install -m 644 "$REPO_DIR/paru-hook.sh" "$HOOK_FILE"
say "installed paru hook to ${c_bold}${HOOK_FILE}${c_off}"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "${c_dim}note: $BIN_DIR is not on your PATH — add it to your shell rc.${c_off}" ;;
esac

# --- config ---------------------------------------------------------------
echo
say "let's set up your provider (bring your own key)"
echo "  Pick a provider, or choose 4 to enter a custom endpoint."
echo "    1) OpenAI       https://api.openai.com/v1"
echo "    2) Anthropic    https://api.anthropic.com/v1"
echo "    3) Ollama       http://localhost:11434/v1   (local, no key)"
echo "    4) custom"
printf 'choice [1]: '; read -r choice || true
case "${choice:-1}" in
    2) endpoint="https://api.anthropic.com/v1"; def_model="claude-haiku-4-5-20251001" ;;
    3) endpoint="http://localhost:11434/v1";    def_model="llama3.1" ;;
    4) printf 'endpoint URL: '; read -r endpoint
       def_model="" ;;
    *) endpoint="https://api.openai.com/v1";     def_model="gpt-4o-mini" ;;
esac

printf 'model slug%s: ' "${def_model:+ [$def_model]}"; read -r model || true
model="${model:-$def_model}"
[ -n "$model" ] || { echo "a model slug is required." >&2; exit 1; }

printf 'API key (input hidden, leave blank for local/no-auth): '
read -rs api_key || true; echo
[ -n "$api_key" ] || api_key="none"

mkdir -p "$CONFIG_DIR"
umask 177  # config holds your key -> create it 0600
cat > "$CONFIG_FILE" <<EOF
# Written by aur-insight setup.sh. Env vars (AUR_INSIGHT_*) override these.
api_key  = $api_key
endpoint = $endpoint
model    = $model
EOF
chmod 600 "$CONFIG_FILE"
say "wrote ${c_bold}${CONFIG_FILE}${c_off} (permissions 600)"

# --- optional paru hook ---------------------------------------------------
echo
printf 'Run aur-insight automatically on every paru install/upgrade? [y/N]: '
read -r hook || true
if [ "${hook:-n}" = "y" ] || [ "${hook:-n}" = "Y" ]; then
    line="source \"$HOOK_FILE\""
    old_line="source \"$REPO_DIR/paru-hook.sh\""
    rc_files=""

    case "${SHELL:-}" in
        *zsh) rc_files="$HOME/.zshrc" ;;
        *bash) rc_files="$HOME/.bashrc" ;;
    esac
    [ -f "$HOME/.zshrc" ] && rc_files="$rc_files $HOME/.zshrc"
    [ -f "$HOME/.bashrc" ] && rc_files="$rc_files $HOME/.bashrc"
    [ -n "$rc_files" ] || rc_files="$HOME/.bashrc"

    for rc in $rc_files; do
        touch "$rc"
        if grep -qsF "$line" "$rc"; then
            say "hook already present in $rc"
        elif grep -qsF "$old_line" "$rc"; then
            tmp="${rc}.aur-insight.$$"
            sed "s|$old_line|$line|g" "$rc" > "$tmp" && mv "$tmp" "$rc"
            say "updated hook path in ${c_bold}${rc}${c_off}"
        else
            printf '\n# aur-insight paru hook\n%s\n' "$line" >> "$rc"
            say "added the hook to ${c_bold}${rc}${c_off}"
        fi
    done
    say "open a new shell, or run: ${c_bold}source \"$HOOK_FILE\"${c_off}"
fi

echo
say "done. Try it:  ${c_bold}aur-insight --dry-run firefox-nightly${c_off}"
say "hook check: ${c_bold}aur-insight-hook-status${c_off} after opening a new shell"
say "or a real review once your key is set: ${c_bold}aur-insight firefox-nightly${c_off}"
