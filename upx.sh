#!/bin/bash

# a wrapper for "post-run" build scripts
# see also https://github.com/rust-lang/cargo/issues/545

tmp=$(mktemp || exit)
trap "rm $tmp" EXIT

cat > $tmp <<"EOF"
prepare() {
    local upxdir="${TMPDIR:-/tmp}/.upx.d3dee1232d4324c2"
    mkdir -p "$upxdir"

    local upx_found=no
    for p in $( find "${upxdir}" \( -name upx -or -name upx.exe \) -exec dirname '{}' \; )
    do
        export PATH="${p}:$PATH"
        upx_found=yes
    done

    if test "$upx_found" != 'yes'
    then
        if ! test -z "$UPX_GNUTAR_DOWNLOAD_URL"
        then
            cd $upxdir
            curl "$UPX_GNUTAR_DOWNLOAD_URL" -v -L -o upx.tar.xx || return
        
            tar vvxf upx.tar.xx || return

	    for p in $( find "${upxdir}" \( -name upx \) -exec dirname '{}' \; )
            do
                export PATH="${p}:$PATH"
            done
            hash -r
            return
        elif ! test -z "$UPX_ZIP_DOWNLOAD_URL"
        then
            cd $upxdir
            curl "$UPX_ZIP_DOWNLOAD_URL" -v -L -o upx.zip || return

            unzip upx.zip || return

	    for p in $( find "${upxdir}" \( -name upx.exe \) -exec dirname '{}' \; )
            do
                export PATH="${p}:$PATH"
            done
            hash -r
            return
        fi
    else
        return
    fi

    if type sudo
    then
        if type apt
        then
            sudo apt install -y upx && return
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
        choco install -y upx && return
    fi

    if type winget
    then
        winget install upx && return
    fi
}

if test -z "$UPX_DISABLE"
then
    prepare

    echo $PATH

    if type upx
    then
        upx --best --lzma $1 && exit
    fi
fi

echo failed to compress binary size by upx, fallback to strip if binary too large...
if test "$(cat $1 | wc -c)" -gt 20971520 # 20M
then
    strip $1
fi
EOF

command $@
status_code="$?"
find "$(realpath ./target/)" \( -name hitdns -or -name hitdns.exe \) -exec bash --norc -x $tmp '{}' \;
exit "$status_code"

