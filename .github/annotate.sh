#!/bin/sh
#
# The end of a file as an annotation of the run this is called in.
#
#   .github/annotate.sh <notice|warning|error> <title> <file> [lines]     default: 60
#
# A run's log takes a login to read. Its annotations do not: they are on the
# run's page and in GitHub's API. So what a job found, and why a step failed,
# is written there, as the suites of tests/ write their totals. A file that is
# missing or empty gives no annotation.
#
# A workflow command is one line: %, a return and a newline are escaped, and
# in the title : and , too. A line is cut at 240 characters, so that a
# compiler's command line does not take the place of what it said.

set -eu

[ $# -ge 3 ] || { echo "usage: annotate.sh <notice|warning|error> <title> <file> [lines]" >&2; exit 2; }
level=$1 title=$2 file=$3 lines=${4:-60}
case $level in
    notice|warning|error) ;;
    *) echo "annotate.sh: notice, warning or error, not: $level" >&2; exit 2 ;;
esac
[ -s "$file" ] || exit 0

title=$(printf '%s' "$title" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/,/%2C/g')
text=$(tail -n "$lines" "$file" | tr -d '\r' | cut -c1-240 | sed -e 's/%/%25/g' | awk '{ printf "%s%%0A", $0 }')
printf '::%s title=%s::%s\n' "$level" "$title" "$text"
