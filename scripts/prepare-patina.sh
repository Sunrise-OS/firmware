#!/bin/sh
# Bring the Patina submodules to the state this repository builds against.
#
#   scripts/prepare-patina.sh
#
# Two submodules are pinned to the commits that published the crates this
# firmware uses, and each carries one small patch on top: see
# `third_party/README.md` for what they are and why. The patches are applied
# idempotently, so this is safe to run before every build, and
# `git -C third_party/<name> checkout .` undoes them.
set -e

here=$(cd "$(dirname "$0")/.." && pwd)

apply() {
    submodule="$here/third_party/$1"
    patch="$here/third_party/patches/$2"

    if [ ! -d "$submodule" ]; then
        echo "the $1 submodule is missing; run: git submodule update --init" >&2
        exit 1
    fi
    if git -C "$submodule" apply --reverse --check "$patch" 2>/dev/null; then
        return 0
    fi
    git -C "$submodule" apply "$patch"
    echo "applied $2 to third_party/$1"
}

apply patina-paging paging-protection-only-attributes.patch
apply patina dxe-core-loaded-image-system-table.patch
