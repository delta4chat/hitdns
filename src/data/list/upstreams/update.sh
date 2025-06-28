#!/bin/bash

set -e
set -x

type curl
type grep
type sort
type tee
type mktemp
type rm

tmp="$(mktemp -d)"
trap "rm -rfv $tmp" EXIT

tmpfile="$tmp/tmpfile"
tmpout="$tmp/tmpout"

url='https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md'

curl "$url" -vL $* -o "$tmpfile"

echo "# Generated time: $(date -u -Is || echo N/A)" > $tmpout
echo "# URL: $url" >> $tmpout
echo >> $tmpout
cat "$tmpfile" | grep -F 'sdns://' | sort -u >> $tmpout

mv -v "$tmpout" dnscrypt.sdns.v3.txt
