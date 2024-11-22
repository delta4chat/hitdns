use crate::*;

pub const DEFAULT_HOSTS_TXT: &'static str =
"
1.0.0.1               one.one.one.one
1.1.1.1               one.one.one.one
2606:4700:4700::1001  one.one.one.one
2606:4700:4700::1111  one.one.one.one

1.0.0.1               cloudflare-dns.com
1.1.1.1               cloudflare-dns.com
2606:4700:4700::1001  cloudflare-dns.com
2606:4700:4700::1111  cloudflare-dns.com

1.0.0.1               dns.cloudflare.com
1.1.1.1               dns.cloudflare.com
2606:4700:4700::1001  dns.cloudflare.com
2606:4700:4700::1111  dns.cloudflare.com

9.9.9.10              dns10.quad9.net
149.112.112.10        dns10.quad9.net
2620:fe::10           dns10.quad9.net
2620:fe::fe:10        dns10.quad9.net

101.101.101.101       dns.twnic.tw
101.102.103.104       dns.twnic.tw
2001:de4::101         dns.twnic.tw
2001:de4::102         dns.twnic.tw

45.11.45.11           dns.sb
185.222.222.222       dns.sb
2a09::                dns.sb
2a11::                dns.sb

94.140.14.140         unfiltered.adguard-dns.com
94.140.14.141         unfiltered.adguard-dns.com
2a10:50c0::1:ff       unfiltered.adguard-dns.com
2a10:50c0::2:ff       unfiltered.adguard-dns.com

130.59.31.248         dns.switch.ch
130.59.31.251         dns.switch.ch
2001:620:0:ff::2      dns.switch.ch
2001:620:0:ff::3      dns.switch.ch
";

pub static HOSTS: Lazy<Hosts> = Lazy::new(|| { smol::block_on(Hosts::new()) });

pub type HostsMap = scc::TreeIndex<String, scc::TreeIndex<IpAddr, ()>>;

#[derive(Debug)]
pub struct Hosts {
    pub(crate) map: HostsMap,
}
impl Hosts {
    async fn new() -> Self {
        if Lazy::get(&HOSTS).is_some() {
            panic!("Hosts{{}} should not be constructed again");
        }

        let this =
            Self {
                map: Default::default(),
            };

        this.parse("<default>", DEFAULT_HOSTS_TXT).await.unwrap();

        this
    }

    pub(crate) fn take(&self) -> HostsMap {
        let map = self.map.clone();
        self.map.clear();
        map
    }

    pub(crate) fn replace(&self, new: &HostsMap) {
        let g = scc::ebr::Guard::new();
        for (domain, ips) in self.map.iter(&g) {
            if new.contains(domain) {
                ips.clear();
                new.peek_with(domain, |_, ips| {
                    for (ip, _) in ips.iter(&g) {
                        let _ = ips.insert(*ip, ());
                    }
                });
            } else {
                self.map.remove(domain);
            }
        }
    }

    pub async fn load(&self, filename: &PathBuf) -> anyhow::Result<()> {
        let text =
            smol::fs::read_to_string(filename).await
            .context("cannot read from hosts.txt file")
            .log_warn()?;

        let (lines, valid) = self.parse(filename.display(), text).await?;

        log::info!("Hosts: loading from {filename:?}: total {lines} lines parsed, and {valid} domain names loaded. mapping: {:#?}", &self.map);

        Ok(())
    }

    pub async fn parse(&self, filename: impl ToString, text: impl ToString) -> anyhow::Result<(usize, usize)> {
        const HOSTS_EXAMPLE: &'static str = "   two examples of hosts.txt that is: 142.250.189.206 ipv4.google.com | 2607:f8b0:4005:814::200e ipv6.google.com   ";

        let filename = filename.to_string();
        let mut text = text.to_string();

        // compatible Unix/Linux LF, Windows CR LF, and Mac CR
        // LF    = \n
        // CR LF = \r\n
        // CR    = \r
        while text.contains("\r") {
            text = text.replace("\r", "\n");
        }
        while text.contains("\n\n") {
            text = text.replace("\n\n", "\n");
        }

        // debug checks
        assert_eq!(text.contains("\r\n"), false);
        assert_eq!(text.contains("\r"), false);
        assert_eq!(text.contains("\n\n"), false);

        let mut lines = 0;
        let mut valid = 0;
        for line in text.split("\n") {
            lines += 1;

            if line.trim().is_empty() {
                continue;
            }

            let mut line = line.to_string();
            // convert all Tab character to space
            while line.contains("\t") {
                line = line.replace("\t", " ");
            }

            // ignore comments or mal-formatted texts.
            if ! line.contains(" ") {
                log::warn!("Hosts: {filename:?}: ignore invalid line: no space character found at line {lines}. / {HOSTS_EXAMPLE}");
                continue;
            }
            if line.replace(" ", "").starts_with("#") {
                continue;
            }

            while line.contains("  ") {
                line = line.replace("  ", " ");
            }
            let words = Vec::from_iter(line.split(" "));
            let words_len = words.len();
            if words_len <= 1 {
                continue;
            }
            let ip: IpAddr = match words[0].parse() {
                Ok(ip) => ip,
                Err(error) => {
                    log::warn!("Hosts: {filename:?}: ignore corrupted line: cannot parse the first word of line {lines} as a IPv4 or IPv6 address: {error:?} / {HOSTS_EXAMPLE}");
                    continue;
                },
            };
            let mut domain = words[1].to_string();
            if ! domain.ends_with(".") {
                domain.push('.');
            }
            let domain = domain.to_ascii_lowercase();

            // any words following the first and last word, expect these is comments.
            if words.len() > 2 {
                log::debug!("Hosts: {filename:?}: ignore tailing words of line {lines}.");
            }

            let _ = self.map.insert_async(domain.clone(), Default::default()).await;
            self.map.peek_with(&domain, |_, ips| { let _ = ips.insert(ip, ()); });

            valid += 1;
        }

        Ok((lines, valid))
    }

    pub fn lookup(&self, domain: impl ToString) -> Option<Vec<IpAddr>> {
        let mut domain: String = domain.to_string();
        if ! domain.ends_with(".") {
            domain.push('.');
        }
        let domain = domain.to_ascii_lowercase();

        self.map.peek_with(&domain, |_, ips| {
            let g = scc::ebr::Guard::new();
            ips.iter(&g).map(|(ip, _)| { *ip }).collect()
        })
    }

    fn _reqwest_resolve(
        &self,
        domain: reqwest_h3::dns::Name,
    ) -> reqwest_h3::dns::Resolving {
        Box::pin(async move {
            let mut addrs: Vec<SocketAddr> = vec![];

            if let Some(ips) = HOSTS.lookup(domain.as_str()) {
                // this is a stupid design by reqwest developers
                // they said "Since the DNS protocol has no notion of ports, ... any port in the overridden addr will be ignored and traffic sent to the conventional port for the given scheme (e.g. 80 for http)."
                // so why this API does not accept Vec<IpAddr> as argument type instead of Vec<SocketAddr> ?!
                // alao the same problem exists at reqwest::ClientBuilder::resolve method
                //
                // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve_to_addrs
                // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve

                for ip in ips.iter() {
                    if HITDNS_OPT.disable_ipv6 && ip.is_ipv6() {
                        continue;
                    }
                    addrs.push(SocketAddr::new(*ip, 0));
                }
            }

            if addrs.is_empty() {
                let msg = format!("DNS static resolve failed: unable to find a mapping from {domain:?} to IPv4/IPv6 addresses.");
                log::warn!("{}", &msg);
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(std::io::ErrorKind::Unsupported, msg));
                return Err(err);
            }

            let iter: Box<dyn Iterator<Item = SocketAddr> + Send> = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

impl reqwest_h3::dns::Resolve for Hosts {
    fn resolve(&self, domain: reqwest_h3::dns::Name) -> reqwest_h3::dns::Resolving {
        self._reqwest_resolve(domain)
    }
}
impl reqwest_h3::dns::Resolve for &Hosts {
    fn resolve(&self, domain: reqwest_h3::dns::Name) -> reqwest_h3::dns::Resolving {
        self._reqwest_resolve(domain)
    }
}

