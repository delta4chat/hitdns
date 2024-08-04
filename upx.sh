#!/bin/bash

# a wrapper for "post-run" build scripts
# see also https://github.com/rust-lang/cargo/issues/545

tmp=$(mktemp || exit)

cat > $tmp <<"EOF"
prepare() {
    if type sudo
    then
        if type apt
        then
            sudo apt install upx && return
        fi

	# disable in macos
	return 1

        if type brew
        then
    	    brew install upx && return
        fi

        if type port
        then
    	    sudo port install upx && return
        fi
    fi

    if type choco
    then
        choco install upx && return
    fi

    if type winget
    then
        winget install upx && return
    fi
}

prepare

if type upx
then
	upx -9 $1 && exit
fi

echo failed to compress binary size by upx, fallback to strip if binary too large...
if test "$(cat $1 | wc -c)" -gt 20971520 # 20M
then
    strip $1
fi
EOF

command $*
status_code="$?"
find ./target/ \( -name hitdns -or -name hitdns.exe \) -exec bash --norc -x $tmp '{}' \;
exit "$status_code"

