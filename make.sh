#!/bin/bash

set -e
set -x

export RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"

cargo_jobs=20

# read from environment variables: ARCH, OS, LIBC

case "$ARCH" in
    amd64 | x86-64 | x86_64 | x64)
	arch="amd64"
	;;
    aarch64 | arm64)
        arch="aarch64"
	;;
    mipsel)
	arch="mipsel"
	;;
    armv7 | arm | armsf | armv7sf)
	arch="armv7"
	;;
    armv7hf | armhf)
	arch="armv7hf"
	;;
    i686 | x86)
        arch="i686"
	;;
    *)
        echo "unknown CPU arch $ARCH"
	exit 1
	;;
esac

case "$OS" in
    linux | lin)
	os="linux"
	;;
    android)
	os="android"
	;;
    mac | macos | darwin | osx)
	os="darwin"
	;;
    windows | win)
        os="windows"
	unset RUSTFLAGS
	;;
    freebsd | fbsd)
	os="freebsd"
	;;
    netbsd | nbsd)
        os="netbsd"
	;;
    openbsd | obsd)
	os="openbsd"
	;;
    *)
        echo "unknown OS $OS"
	exit 2
	;;
esac

case "$LIBC" in
    gnu)
	libc="gnu"
	;;
    musl)
	libc="musl"
	;;
    msvc)
	libc="msvc"
	;;
    *)
	echo "does not specifiy a valid libc (${LIBC}), default to gnu (glibc)"
	libc="gnu"
	;;
esac

if test "libc" = "msvc" && test "$os" != "windows"
then
    echo "os=$os does not support msvc"
    exit 10
fi


target_arch="$arch"
if test "$arch" = "amd64"
then
    target_arch="x86_64"
fi

case "$os" in
    android)
	echo "os=android: ignore libc=$libc"
        case "$arch" in
            aarch64)
                target="aarch64-linux-android"
		;;
	    amd64)
		target="x86_64-linux-android"
		;;
	    armv7 | armv7hf)
		target="armv7-linux-androideabi"
		;;
	    *)
		echo "os=android does not support arch=$arch"
		exit 20
		;;
	esac
	;;
    linux)
	case "$arch" in
	    armv7)
		libc="${libc}eabi"
		;;
	    armv7hf)
		target_arch="armv7"
		libc="${libc}eabihf"
		;;
	    amd64 | aarch64 | i686 | armv7 | armv7hf | mipsel)
		;;
	    *)
		echo "os=linux does not support arch=$arch"
		exit 21
		;;
	esac

	target="${target_arch}-unknown-linux-${libc}"
	;;
    freebsd)
	echo "os=freebsd: ignore libc=$libc"
	case "$arch" in
	    amd64 | aarch64 | i686)
		;;
	    *)
		echo "os=freebsd does not support arch=$arch"
		exit 22
		;;
	esac
	target="${target_arch}-unknown-freebsd"
	;;
    netbsd)
	echo "os=netbsd: ignore libc=$libc"
	if "$arch" != "amd64"
	then
	    echo "os=netbsd does not arch=$arch"
	    exit 23
	fi
	target="${target_arch}-unknown-netbsd"
	;;
    openbsd)
	echo "TODO: openbsd support"
	exit 24
	;;
    *)
	echo "bug: unreachable"
	exit 25
	;;
esac

case "$target" in
    x86_64-unknown-linux-* | x86_64-apple-darwin | aarch64-apple-darwin | x86_64-*-windows-* )
	cross="no"
	;;
    *)
        cross="yes"
	;;
esac

if test "$arch" = "i686" && test "$os" = "linux"
then
    echo "not to use nightly due to rustix 'naked_asm!' issue"
    cargo_args=""
else
    echo "use nightly rust toolchain..."
    rustup default nightly
    rustup component add rust-src
    cargo_args="-Z build-std=core,alloc,std,proc_macro"
fi

if test "$cross" = "yes"
then
    RUSTFLAGS='' cargo install cross --jobs "$cargo_jobs"

    cross build --target "$target" --jobs "$cargo_jobs" $cargo_args $@
    status_code="$?"
else
    cargo build --target "$target" --jobs "$cargo_jobs" $cargo_args $@
    status_code="$?"
fi

exit $status_code

