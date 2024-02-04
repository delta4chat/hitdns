#!/bin/bash

# a warpper for "post-run" build scripts
# see also https://github.com/rust-lang/cargo/issues/545

tmp=$(mktemp || exit)

tee $tmp <<"EOF"
if type upx
then
	upx $1 && exit
fi

if type xz
then
	xz -v -e -9 -T8 $1 && mv $1.xz $1
elif type gzip
then
	gzip -9 $1 && mv $1.gz $1
else
	echo failed to compress file size, fallback to strip?
fi
EOF

command $*
status_code="$?"
find ./target/ \( -name hitdns -or -name hitdns.exe \) -exec sh $tmp '{}' \;
exit "$status_code"

