## fix domain `foo_bar.com` resolve fails:
* [x] fixed?
1. this is not our problems, it cause by upstream library `hickory-proto` (for dns message parse)
```
thread 'sscale-wkr-c-7' panicked at src/types.rs:37:14:
cannot convert to hickory Query: Label contains invalid characters: Err(Errors { invalid_mapping, disallowed_by_std3_ascii_rules })                                 
note: run with RUST_BACKTRACE=1 environment variable to display a backtrace
```

## add a config file instead of command line arguments
* [x] completed TOML config file

~~1. use YAML, TOML, or JSON?~~

## more useful API operations
1. [ ] such as restart, stop, or update binary
2. [ ] reload configure file
3. [ ] dynamic change DNS records?

## Other one-line things
1. [x] create README.md
2. [ ] add ACL rules
3. [ ] add support for LAN devices lookups, for example `.local` / `.lan` domains. (should forward it to gateway DNS such as `192.168.1.1`?)
4. [x] add hosts support for DNS resolving
5. [ ] \(optional) add network offline detects?
6. [x] \(optional) ~~add automatic update expired cache entry?~~ implements API endpoint for requesting Record expire. instead of "automatic update" (which uses a lot of bandwidth due to refreshing ALL dns queries received in the past, and may be exploited by DDoS attacks as a traffic reflection amplifier)
7. [ ] CI: build.yml: use matrix instead of duplicate codes (partial complete)
8. [ ] CI: build.yml: (optional) add support for arm windows
9. [ ] implement [RFC 8427](https://www.rfc-editor.org/rfc/rfc8427) JSON output
10. [ ] add more rdtype output in dohp `/resolve`
