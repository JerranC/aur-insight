# aur-insight :: paru auto-hook for fish
#
# This wraps `paru` so aur-insight reviews AUR packages before paru reaches its
# normal confirmation prompt.

set -q AUR_INSIGHT_BIN; or set -g AUR_INSIGHT_BIN aur-insight
set -g AUR_INSIGHT_HOOK_PATH (status filename)

function paru --wraps paru
    if set -q AUR_INSIGHT_OFF
        command paru $argv
        return $status
    end

    if not command -q $AUR_INSIGHT_BIN
        command paru $argv
        return $status
    end

    set -l mode --diff
    if set -q AUR_INSIGHT_DEEP
        set mode --deep
    end

    set -l op
    set -l pkgs
    for arg in $argv
        switch $arg
            case '-S*u*' '-*yu' '-*Syu' '--sysupgrade'
                set op upgrade
            case '-S' '-S*'
                test -z "$op"; and set op install
            case '-*'
            case '*'
                set -a pkgs $arg
        end
    end

    if test "$op" = upgrade
        printf '\n[aur-insight] reviewing pending AUR updates before paru...\n' >&2
        command $AUR_INSIGHT_BIN $mode --syu
    else if test "$op" = install; and test (count $pkgs) -gt 0
        set -l pkg_text (string join ' ' $pkgs)
        printf '\n[aur-insight] reviewing %s before paru...\n' "$pkg_text" >&2
        command $AUR_INSIGHT_BIN $mode $pkgs
    end

    command paru $argv
end

function aur-insight-hook-status
    if set -q AUR_INSIGHT_OFF
        echo "aur-insight hook: disabled by AUR_INSIGHT_OFF"
        return 1
    end
    if not command -q $AUR_INSIGHT_BIN
        echo "aur-insight hook: $AUR_INSIGHT_BIN not found on PATH"
        return 1
    end
    if functions -q paru
        echo "aur-insight hook: active ($AUR_INSIGHT_BIN)"
        echo "aur-insight hook: sourced from $AUR_INSIGHT_HOOK_PATH"
        return 0
    end
    echo "aur-insight hook: not active in this shell; source paru-hook.fish"
    return 1
end
