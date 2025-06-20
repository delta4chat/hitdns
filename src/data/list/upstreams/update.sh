#!/bin/bash

set -e
set -x

type curl
type grep
type sort
type tee

tmpfile="$(mktemp)"
trap "rm -rfv $tmpfile" EXIT

url='https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md'

echo "# Generated time: $(date -u -Is || echo N/A)" > $tmpfile
echo "# URL: $url" >> $tmpfile
echo >> $tmpfile

curl "$url" -vL $* | grep -F 'sdns://' | sort -u >> $tmpfile

mv -v $tmpfile dnscrypt.sdns.v3.txt
trap 'true' EXIT
