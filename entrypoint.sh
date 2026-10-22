#!/bin/bash
# RustPacker All-in-One Container Entrypoint
#
# Sets up the cross-compilation environment, makes sure the generated payload
# always lands on the host (in the directory mounted at /workdir), and
# delegates to the RustPacker binary. Argument parsing, validation, alias
# conversion and help/version output are all handled by the binary itself
# (clap) - this script intentionally does not duplicate that logic.

export PATH="/usr/local/cargo/bin:/usr/local/rustup/shims:$PATH"
export CARGO_HOME=/usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup
export CFLAGS_x86_64_pc_windows_gnu="-lrt"
export LDFLAGS_x86_64_pc_windows_gnu="-lrt"

# Templates and project files live in /app inside the container
cd /app

# Host path bind-mounted at /workdir, recovered from mountinfo (best effort)
host_workdir_root() {
    awk '$5 == "/workdir" { print $4 }' /proc/self/mountinfo | tail -n 1
}

# Value of a short/long flag among "$@": "-f x", "-fx", "-f=x",
# "--format x" or "--format=x". Prints the fallback when absent.
flag_value() {
    local flag_short="$1" flag_long="$2" fallback="$3"
    shift 3
    local prev="" value=""
    for arg in "$@"; do
        if [ -n "$prev" ]; then value="$arg"; break; fi
        case "$arg" in
            "$flag_long" | "$flag_short") prev="1" ;;
            "$flag_short"?*)
                value="${arg#"$flag_short"}"
                value="${value#=}"
                break
                ;;
            "$flag_long"=?*) value="${arg#"$flag_long"=}"; break ;;
        esac
    done
    echo "${value:-$fallback}"
}

format="$(flag_value -f --format exe "$@")"
output="$(flag_value -o --output "" "$@")"

# Default the output to the mounted directory so the payload survives the
# container; without a mount the binary falls back to its own default.
if [ -z "$output" ] && [ -d /workdir ]; then
    output="/workdir/payload.$format"
    set -- "$@" --output "$output"
fi

rustpacker "$@"
rc=$?

if [ "$rc" -eq 0 ] && [ -n "$output" ]; then
    case "$output" in
        /workdir | /workdir/*)
            host_root="$(host_workdir_root)"
            if [ -n "$host_root" ]; then
                echo "[i] On your machine, the payload is at: $host_root${output#/workdir}"
            else
                echo "[i] /workdir is the directory you mounted with -v; the payload is at: $output"
            fi
            ;;
        *)
            echo "[!] The payload was written inside the container ($output) and will be lost when it exits."
            echo "[!] Mount a directory (-v \$(pwd):/workdir) and use --output /workdir/... to keep the payload."
            ;;
    esac
fi

exit "$rc"
