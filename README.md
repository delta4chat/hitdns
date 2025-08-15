# [NOTE] the development of this branch is temporary paused due to code-refactor in progress at https://github.com/delta4chat/hitdns/tree/refactor

After code refactoring, the following issues are expected to be resolved:
1. the problem of untimely update, currently it takes 2~3 queries for a 0 TTL expired record to trigger the update, the reason is unknown.
2. the current HTTP API is not standardized, it is expected to use the REST API standard instead, and achieve API consistency.
3. EDNS in wire format is currently forced to be stripped, in the future it will be changed to be configurable whether to keep it or not.
4. the database format (sqlite3) is not pure-Rust (slowly to compile), it is expected to use `sled` with some async wrapper instead.
5. the `reqwest` crate is depends to tokio, it is expected to use another HTTPS client that can working properly for `smol` ecosystem instead.
6. the CLI arguments configuration will be completely replaced by file-based configuration.
7. improved logging library using `log4rs`.
8. add support for DNS Stamp (`sdns://`) URL format to define upstream servers.
9. add more DNS ustream protocols, e.g. DNSCrypt, DNS over QUIC, DNS over HTTP/3.

# Hit DNS - Probably the world's fastest DNS forwarder 
[![crates.io](https://img.shields.io/crates/v/hitdns)](https://crates.io/crates/hitdns)
<!-- [![docs.rs](https://img.shields.io/docsrs/hitdns)](https://docs.rs/hitdns) -->


[![License](https://img.shields.io/crates/l/hitdns)](https://github.com/delta4chat/hitdns/blob/master/LICENSE.txt)

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/delta4chat/hitdns/build.yml?branch=master)](https://github.com/delta4chat/hitdns/actions/workflows/build.yml)
[![GitHub Tag](https://img.shields.io/github/v/tag/delta4chat/hitdns)](https://github.com/delta4chat/hitdns/tags)
[![GitHub last commit](https://img.shields.io/github/last-commit/delta4chat/hitdns)](https://github.com/delta4chat/hitdns/commits/master)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/delta4chat/hitdns)

hitdns has low query latency and a high cache hit rate. This is because it will return the last available DNS resolution result whenever possible (regardless of whether its TTL has expired) and if it does expired, it will start an update task in the background, instead of "waiting for the upstream DNS recursor to return the latest result" like other DNS resolvers (e.g. dnsmasq).

So hitdns users will only experience delays the first time they query a domain they've never queried before, and every time they query this domain after that, they'll get near-instantaneous response latency.

## How to clone this repository
the `bin` branch contains a lot of large files for pre-compiled binaries, you may want to exclude these large files, you can clone only `master` branch that contains source code only.

`git clone https://github.com/delta4chat/hitdns --single-branch`

or just filter these blobs

`git clone https://github.com/delta4chat/hitdns --filter=blob:limit=1M`

