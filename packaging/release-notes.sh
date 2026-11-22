#!/bin/sh
#
# The notes of a release, on standard output: what CHANGELOG.md says of the
# version in lightbox.h, then how to install the files of the release and how
# to check one that was downloaded.
#
#   packaging/release-notes.sh > notes.md
#
# The release workflow gives them to the draft release it makes. A tree
# between two releases, 0.9.0-dev, gets the notes of 0.9.0 as far as they are
# written. GITHUB_REPOSITORY names the repository whose record of a build is
# asked for; it is OzkrAC/lightbox where nothing sets it.

set -eu

cd "$(dirname "$0")/.."

version=$(sh packaging/version.sh)
release=${version%-dev}
deb=$(sh packaging/version.sh deb)
xbps=$(sh packaging/version.sh xbps)
repo=${GITHUB_REPOSITORY:-OzkrAC/lightbox}

awk -v head="## $release" '
    $0 == head       { on = 1; found = 1; next }
    /^## /           { on = 0 }
    on               { print }
    END              { if (!found) exit 3 }
' CHANGELOG.md > /dev/null || { echo "release-notes: CHANGELOG.md has no section \"## $release\"" >&2; exit 1; }

# the section, without the blank lines at its two ends
awk -v head="## $release" '
    $0 == head       { on = 1; next }
    /^## /           { on = 0 }
    on && !seen && $0 == "" { next }
    on               { seen = 1; held = held $0 "\n"; if ($0 != "") { printf "%s", held; held = "" } }
' CHANGELOG.md

cat <<EOF

## Installing

Debian and Ubuntu, on amd64 or arm64:

\`\`\`sh
sudo apt install ./lightbox_${deb}-1_amd64.deb
\`\`\`

Void Linux, with glibc or with musl, on x86_64 or aarch64, in the directory the package is in:

\`\`\`sh
xbps-rindex -a lightbox-${xbps}_1.*.xbps
sudo xbps-install --repository="\$PWD" lightbox
\`\`\`

A package holds the binary, its manual page and an example configuration, and starts nothing. \`lightbox doctor\` says what the machine lacks, and \`sudo lightbox setup\` makes the network.

\`lightbox-${version}.tar.gz\` is the source, with lightc's inside: it builds with \`make\` and no network. The two archives of source code that GitHub adds to a release by itself leave lightc out and do not build.

## Checking a download

\`SHA256SUMS\` has the SHA-256 of every file here, and GitHub keeps a signed record of the run that built each of them:

\`\`\`sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify lightbox_${deb}-1_amd64.deb --repo ${repo}
\`\`\`
EOF
