# Shared case runner for the lightbox test suites. Source it; do not run it.
#
#   check NAME FUNCTION
#       The function must succeed.
#
#   xfail LEDGER-ID NAME FUNCTION
#       An open finding from ROADMAP.md. The function states the correct
#       behaviour and is expected to fail. When it starts passing, the suite
#       fails until the line is changed to "check", so a fix cannot land
#       without being recorded in the suite.
#
#   summary SUITE-NAME
#       Prints the totals. Fails if any case failed or passed unexpectedly.
#
# A case function returns 0 to pass, 77 to skip and anything else to fail. Its
# output is shown only when the result is not the expected one, or with V=1.
#
# A suite may define case_setup, which runs before each case in the same
# subshell and receives the case number; SHOW_FILTER, a sed expression applied
# to the output that is shown; and SHOW_LINES, how many lines of it to show
# (40 unless set). A suite may also replace run_case after sourcing this file.
#
# Under GitHub Actions a failed case and an unexpected pass are also written as
# error annotations, and the totals as a notice that names every skipped case.
# A second notice gives the last line each expected failure printed, so that a
# reader can see it fails for the reason its name gives and not for another.
# The run's summary page lists annotations without the log.

n=0 passed=0 failed=0 xfailed=0 xpassed=0 skipped=0
skipped_names=""
xfail_last_lines=""

run_case() { # function -> sets rc and out
    n=$((n + 1))
    out=$( {
        if declare -F case_setup >/dev/null; then case_setup "$n"; fi
        "$1"
    } 2>&1 )
    rc=$?
}

show() {
    [ -n "$out" ] || return 0
    printf '%s\n' "$out" | sed -e "${SHOW_FILTER:-s/^//}" -e 's/^/       | /' | head -n "${SHOW_LINES:-40}"
}

annotate() { # title: the case's output as a GitHub Actions error annotation
    [ "${GITHUB_ACTIONS:-}" = true ] || return 0
    local title text
    # a workflow command is one line: %, newlines, and in a property : and , are escaped
    title=$(printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/,/%2C/g')
    text=$(printf '%s\n' "$out" | sed -e "${SHOW_FILTER:-s/^//}" | head -n 20 |
           sed -e 's/%/%25/g' | awk '{ printf "%s%%0A", $0 }')
    printf '::error title=%s::%s\n' "$title" "${text:-no output}"
}

check() { # name, function
    run_case "$2"
    if [ $rc -eq 0 ]; then
        passed=$((passed + 1)); printf 'ok     %s\n' "$1"
        [ "${V:-0}" = 1 ] && show
    elif [ $rc -eq 77 ]; then
        skipped=$((skipped + 1)); printf 'skip   %s\n' "$1"; show
        skipped_names="${skipped_names:+$skipped_names; }$1"
    else
        failed=$((failed + 1)); printf 'FAIL   %s\n' "$1"; show
        annotate "FAIL: $1"
    fi
    return 0
}

xfail() { # ledger id, name, function
    run_case "$3"
    if [ $rc -eq 77 ]; then
        skipped=$((skipped + 1)); printf 'skip   %s\n' "$2"; show
        skipped_names="${skipped_names:+$skipped_names; }$2"
    elif [ $rc -ne 0 ]; then
        xfailed=$((xfailed + 1)); printf 'xfail  %-22s %s\n' "$1" "$2"
        [ "${V:-0}" = 1 ] && show
        xfail_last_lines="$xfail_last_lines$1 | $2 | $(printf '%s\n' "$out" | sed -e "${SHOW_FILTER:-s/^//}" |
            awk 'NF { last = $0 } END { print substr(last, 1, 200) }')
"
    else
        xpassed=$((xpassed + 1))
        printf 'XPASS  %-22s %s\n' "$1" "$2"
        printf '       | passes now: change this case from xfail to check\n'
        [ "${V:-0}" = 1 ] && show
        annotate "XPASS: $2 ($1 passes now)"
    fi
    return 0
}

summary() { # suite name
    local totals
    totals="$passed passed, $xfailed expected failures, $failed failed, $xpassed unexpected passes, $skipped skipped"
    printf '\n%s: %s\n' "$1" "$totals"
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '::notice title=%s suite::%s\n' "$1" \
            "$(printf '%s' "$totals${skipped_names:+. Skipped: $skipped_names}" | sed -e 's/%/%25/g')"
        if [ -n "$xfail_last_lines" ]; then
            printf '::notice title=%s suite - last line of each expected failure::%s\n' "$1" \
                "$(printf '%s' "$xfail_last_lines" | sed -e 's/%/%25/g' | awk '{ printf "%s%%0A", $0 }')"
        fi
    fi
    [ "$failed" -eq 0 ] && [ "$xpassed" -eq 0 ]
}
