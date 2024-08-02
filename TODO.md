## fix domain `foo_bar.com` resolve fails:
* [x] fixed?
1. this is not our problems, it cause by upstream library `hickory-proto` (for dns message parse)
```
thread 'sscale-wkr-c-7' panicked at src/types.rs:37:14:
cannot convert to hickory Query: Label contains invalid characters: Err(Errors { invalid_mapping, disallowed_by_std3_ascii_rules })                                 
note: run with RUST_BACKTRACE=1 environment variable to display a backtrace
```

## add a config file instead of command line arguments
* [ ] fixed?
1. use YAML, TOML, or JSON?

## more useful API operations
1. [ ] such as restart, stop, or update binary
2. [ ] reload configure file
3. [ ] dynamic change DNS records?

## Other one-line things
1. [ ] create README.md
2. [ ] add ACL rules
3. [ ] add support for LAN devices lookups, for example `.local` / `.lan` domains. (should forward it to gateway DNS such as `192.168.1.1`?)
4. [ ] add hosts support for DNS resolving
5. [ ] \(optional) add network offline detects?
6. [ ] \(optional) add automatic update expired cache entry?

