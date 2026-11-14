#!/usr/bin/env bash
# Static analysis of the lightbox sources (scratch copy). Read-only w.r.t. the repos.
set -u
S=/tmp/claude-1000/-home-c0dr-ozkr-ac-endeavor-lightbox/ee7507ce-59b0-47cb-9e8f-cde3b30f88a2/scratchpad
SRC="$S/build/lightbox"
OUT="$S/analysis"
FILES=(lightbox.c lightbox_meta.c lightbox_state.c lightbox_net.c lightbox_config.c lightbox_util.c)
BASE=(-std=c23 -O2 -DNDEBUG -ffreestanding -nostdlib -fno-stack-protector "-I$S/build/lightc/include" -c -o /dev/null
      -fdiagnostics-plain-output -fno-diagnostics-show-caret)

cd "$SRC" || exit 1

run() { # name, extra flags...
  local name=$1; shift
  : > "$OUT/$name.txt"
  for f in "${FILES[@]}"; do
    gcc "${BASE[@]}" "$@" "$f" 2>&1 | grep -E "(warning|error):" >> "$OUT/$name.txt"
  done
  echo "##### $name: $(wc -l < "$OUT/$name.txt") diagnostics"
}

run analyzer   -Wall -Wextra -fanalyzer
run strict     -Wall -Wextra -Wshadow -Wformat=2 -Wnull-dereference -Wuninitialized -Wmaybe-uninitialized \
               -Wstrict-overflow=2 -Wcast-align=strict -Wcast-qual -Wwrite-strings -Wundef -Wunused-macros \
               -Wredundant-decls -Wmissing-prototypes -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
               -Wstringop-overflow=4 -Warray-bounds=2 -Walloca -Wvla
run conversion -Wconversion -Wsign-conversion
