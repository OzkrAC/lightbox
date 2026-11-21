#!/bin/sh
# Part of the seccomp suite's workload (ROADMAP 8.3), run in an empty
# directory: a repository made, committed to and cloned twice, once by the
# local shortcut and once through upload-pack, as a fetch from elsewhere is.
set -eu
export HOME="$PWD" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
git init -q src
echo one > src/file
git -C src add file
git -C src -c user.name=lightbox -c user.email=lightbox@example.invalid commit -qm first
git clone -q src copy
git clone -q --no-local src fetched
[ "$(cat copy/file)" = one ]
[ "$(git -C fetched log --format=%s)" = first ]
echo "a repository made and cloned twice"
