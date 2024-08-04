# Hit DNS - Probably the world's fastest DNS forwarder 
[![crates.io](https://img.shields.io/crates/v/hitdns)](https://crates.io/crates/hitdns)
[![docs.rs](https://img.shields.io/docsrs/hitdns)](https://docs.rs/hitdns)


[![License](https://img.shields.io/crates/l/hitdns)](https://github.com/delta4chat/hitdns/blob/master/LICENSE.txt)

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/delta4chat/hitdns/build.yml?branch=master)](https://github.com/delta4chat/hitdns/actions/workflows/build.yml)
[![GitHub Tag](https://img.shields.io/github/v/tag/delta4chat/hitdns)](https://github.com/delta4chat/hitdns/tags)
[![GitHub last commit](https://img.shields.io/github/last-commit/delta4chat/hitdns)](https://github.com/delta4chat/hitdns/commits/master)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/delta4chat/hitdns)

hitdns has low query latency and a high cache hit rate. This is because it will return the last available DNS resolution result whenever possible (regardless of whether its TTL has expired) and if it does expired, it will start an update task in the background, instead of "waiting for the upstream DNS recursor to return the latest result" like other DNS resolvers (e.g. dnsmasq).

So hitdns users will only experience delays the first time they query a domain they've never queried before, and every time they query this domain after that, they'll get near-instantaneous response latency.

