# aur-insight :: paru auto-hook
# ---------------------------------------------------------------------------
# Source this from your ~/.bashrc or ~/.zshrc:
#
#     source /path/to/aur-insight/paru-hook.sh
#
# It wraps `paru` so that whenever you install or upgrade, aur-insight runs an
# LLM security review of the affected AUR packages FIRST and prints a verdict.
# paru then continues with its normal confirmation prompt — aur-insight is
# purely advisory and never installs or aborts anything on its own.
#
# By default the hook runs in --diff mode: on an update it reviews only what
# changed since your installed version (packaging + source build scripts), and
# on a fresh install it falls back to reviewing the full source payload.
#
# Set AUR_INSIGHT_BIN if aur-insight isn't on your PATH as `aur-insight`.
# Set AUR_INSIGHT_OFF=1 to temporarily disable the hook without unsourcing it.
# Set AUR_INSIGHT_DEEP=1 to always review the FULL payload (not just the diff).

AUR_INSIGHT_BIN="${AUR_INSIGHT_BIN:-aur-insight}"
[ -n "${AUR_INSIGHT_DEEP:-}" ] && AUR_INSIGHT_MODE="--deep" || AUR_INSIGHT_MODE="--diff"

paru() {
    # Bail out cleanly if disabled or the tool is missing.
    if [ -n "${AUR_INSIGHT_OFF:-}" ] || ! command -v "$AUR_INSIGHT_BIN" >/dev/null 2>&1; then
        command paru "$@"
        return $?
    fi

    local op="" pkgs=()
    for arg in "$@"; do
        case "$arg" in
            -S*u*|-*yu|-*Syu|--sysupgrade) op="upgrade" ;;   # -Syu, -Su, -Sua...
            -S|-S[a-z]*) [ -z "$op" ] && op="install" ;;      # plain install
            -*) ;;                                            # other flags
            *) pkgs+=("$arg") ;;                              # package targets
        esac
    done

    if [ "$op" = "upgrade" ]; then
        "$AUR_INSIGHT_BIN" $AUR_INSIGHT_MODE --syu
    elif [ "$op" = "install" ] && [ "${#pkgs[@]}" -gt 0 ]; then
        "$AUR_INSIGHT_BIN" $AUR_INSIGHT_MODE "${pkgs[@]}"
    fi

    # Hand off to the real paru, which runs its own confirmation prompt.
    command paru "$@"
}

aur-insight-hook-status() {
    if [ -n "${AUR_INSIGHT_OFF:-}" ]; then
        echo "aur-insight hook: disabled by AUR_INSIGHT_OFF"
        return 1
    fi
    if ! command -v "$AUR_INSIGHT_BIN" >/dev/null 2>&1; then
        echo "aur-insight hook: $AUR_INSIGHT_BIN not found on PATH"
        return 1
    fi
    if type paru 2>/dev/null | grep -q "function"; then
        echo "aur-insight hook: active ($AUR_INSIGHT_MODE, $AUR_INSIGHT_BIN)"
        return 0
    fi
    echo "aur-insight hook: not active in this shell; source paru-hook.sh"
    return 1
}
