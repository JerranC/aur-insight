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

usage() {
    cat <<EOF
usage: ./setup.sh [--upgrade|--uninstall|--purge-config]

  no args        interactive install/reinstall
  --upgrade      update the CLI + hook file, keep existing config
  --uninstall    remove the CLI + shell hook, keep config/cache
  --purge-config remove config and cache too (only with --uninstall)
EOF
}

rc_files() {
    local files=""
    case "${SHELL:-}" in
        *zsh) files="$HOME/.zshrc" ;;
        *bash) files="$HOME/.bashrc" ;;
    esac
    [ -f "$HOME/.zshrc" ] && files="$files $HOME/.zshrc"
    [ -f "$HOME/.bashrc" ] && files="$files $HOME/.bashrc"
    [ -n "$files" ] || files="$HOME/.bashrc"
    printf '%s\n' $files | awk '!seen[$0]++'
}

install_files() {
    say "installing the CLI to ${c_bold}${BIN_DIR}/aur-insight${c_off}"
    mkdir -p "$BIN_DIR"
    install -m 755 "$REPO_DIR/aur_insight.py" "$BIN_DIR/aur-insight"
    mkdir -p "$DATA_DIR"
    install -m 644 "$REPO_DIR/paru-hook.sh" "$HOOK_FILE"
    say "installed paru hook to ${c_bold}${HOOK_FILE}${c_off}"
}

migrate_hook_paths() {
    local line old_line rc tmp
    line="source \"$HOOK_FILE\""
    old_line="source \"$REPO_DIR/paru-hook.sh\""

    while IFS= read -r rc; do
        [ -f "$rc" ] || continue
        if grep -qsF "$line" "$rc"; then
            say "hook already present in $rc"
        elif grep -qsF "$old_line" "$rc"; then
            tmp="${rc}.aur-insight.$$"
            sed "s|$old_line|$line|g" "$rc" > "$tmp" && mv "$tmp" "$rc"
            say "updated hook path in ${c_bold}${rc}${c_off}"
        elif grep -qsE '^[[:space:]]*source .*paru-hook[.]sh' "$rc"; then
            tmp="${rc}.aur-insight.$$"
            sed -E "s|^[[:space:]]*source .*paru-hook[.]sh.*$|$line|g" "$rc" > "$tmp" && mv "$tmp" "$rc"
            say "migrated existing paru hook in ${c_bold}${rc}${c_off}"
        fi
    done < <(rc_files)
}

add_hook_to_rcs() {
    local line rc
    line="source \"$HOOK_FILE\""
    migrate_hook_paths

    while IFS= read -r rc; do
        touch "$rc"
        if grep -qsF "$line" "$rc"; then
            continue
        fi
        printf '\n# aur-insight paru hook\n%s\n' "$line" >> "$rc"
        say "added the hook to ${c_bold}${rc}${c_off}"
    done < <(rc_files)
}

remove_hook_from_rcs() {
    local rc tmp
    while IFS= read -r rc; do
        [ -f "$rc" ] || continue
        tmp="${rc}.aur-insight.$$"
        sed -E '/# aur-insight paru hook/d;/^[[:space:]]*source .*paru-hook[.]sh/d' "$rc" > "$tmp" && mv "$tmp" "$rc"
        say "removed paru hook lines from ${c_bold}${rc}${c_off}"
    done < <(rc_files)
}

purge_config=0
case "${1:-}" in
    --help|-h)
        usage
        exit 0
        ;;
    --purge-config)
        echo "--purge-config must be used with --uninstall." >&2
        usage
        exit 2
        ;;
    --uninstall)
        [ "${2:-}" = "--purge-config" ] && purge_config=1
        [ -z "${3:-}" ] || { usage >&2; exit 2; }
        remove_hook_from_rcs
        rm -f "$BIN_DIR/aur-insight" "$HOOK_FILE"
        rmdir "$DATA_DIR" 2>/dev/null || true
        say "removed CLI and paru hook"
        if [ "$purge_config" -eq 1 ]; then
            rm -rf "$CONFIG_DIR" "${XDG_CACHE_HOME:-$HOME/.cache}/aur-insight"
            say "removed config and cache"
        else
            say "kept config at ${c_bold}${CONFIG_FILE}${c_off}"
        fi
        exit 0
        ;;
    --upgrade)
        [ -z "${2:-}" ] || { usage >&2; exit 2; }
        install_files
        migrate_hook_paths
        say "upgrade complete; kept existing config at ${c_bold}${CONFIG_FILE}${c_off}"
        say "open a new shell, or run: ${c_bold}source \"$HOOK_FILE\"${c_off}"
        exit 0
        ;;
    "")
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

install_files

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
    add_hook_to_rcs
    say "open a new shell, or run: ${c_bold}source \"$HOOK_FILE\"${c_off}"
fi

echo
say "done. Try it:  ${c_bold}aur-insight --dry-run firefox-nightly${c_off}"
say "hook check: ${c_bold}aur-insight-hook-status${c_off} after opening a new shell"
say "or a real review once your key is set: ${c_bold}aur-insight firefox-nightly${c_off}"
