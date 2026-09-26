#!/bin/sh
# Turn a release tag into the version string a CatCard image carries.
#
#   tools/release-version.sh v7.0.0-alpha1   ->  7.0.0a1
#   tools/release-version.sh v7.0.0          ->  7.0.0
#
# The firmware header's version field is 7 ASCII characters and a NUL
# (docs/RELEASING.md, "Version and timestamp"), so a tag cannot go in as it is written.
# A pre-release suffix is folded to one letter and its number: alpha -> a, beta -> b,
# rc -> r. Anything that would still not fit, or that is not shaped like a release tag,
# is refused rather than cut short: two different tags must never stamp the same bytes.
#
# The tag's X.Y.Z must also equal the workspace version in Cargo.toml, so a tag cannot
# publish an image whose crates all say something else.
set -eu

tag=${1:?usage: tools/release-version.sh <tag>}

case "$tag" in
  v*) ;;
  *) echo "tag '$tag' does not start with v" >&2; exit 1 ;;
esac
ver=${tag#v}

base=$(printf '%s' "$ver" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*$/\1/p')
[ -n "$base" ] || { echo "tag '$tag' is not vX.Y.Z[-suffix]" >&2; exit 1; }
rest=${ver#"$base"}

case "$rest" in
  "") short="$base" ;;
  -alpha[0-9]*|-beta[0-9]*|-rc[0-9]*)
    kind=$(printf '%s' "$rest" | sed 's/^-\([a-z]*\)[0-9]*$/\1/')
    num=$(printf '%s' "$rest" | sed 's/^-[a-z]*\([0-9]*\)$/\1/')
    # Both seds must have matched the whole suffix, or the input had something after the
    # number ("-alpha1x"), which is not a tag this knows how to shorten.
    [ "-$kind$num" = "$rest" ] || { echo "tag '$tag': unrecognised suffix '$rest'" >&2; exit 1; }
    case "$kind" in
      alpha) letter=a ;;
      beta)  letter=b ;;
      rc)    letter=r ;;
    esac
    short="$base$letter$num"
    ;;
  *) echo "tag '$tag': suffix '$rest' is not -alphaN, -betaN or -rcN" >&2; exit 1 ;;
esac

if [ "${#short}" -gt 7 ]; then
  echo "tag '$tag' becomes '$short', longer than the header's 7 characters" >&2
  exit 1
fi

# The workspace version, read from [workspace.package] in the root Cargo.toml.
root=$(cd "$(dirname "$0")/.." && pwd)
workspace=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p;}' "$root/Cargo.toml" | head -1)
if [ "$base" != "$workspace" ]; then
  echo "tag '$tag' is $base, but Cargo.toml's workspace version is $workspace" >&2
  exit 1
fi

printf '%s\n' "$short"
