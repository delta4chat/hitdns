#!/bin/bash

set -e
set -x

type curl
type grep
type sort

curl https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md -vL | grep -F 'sdns://' | sort -u | tee dnscrypt.sdns.v3.txt
