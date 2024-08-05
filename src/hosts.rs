use crate::*;

pub static HOSTS: Lazy<Hosts> =
    Lazy::new(|| Hosts::new());

#[derive(Debug)]
pub struct Hosts {
    pub(crate) map: scc::HashMap<String, Vec<IpAddr>>,
}
impl Hosts {
    fn new() -> Self {
        if Lazy::get(&HOSTS).is_some() {
            panic!("Hosts{{}} should not be constructed again");
        }

        Self {
            map: scc::HashMap::new(),
        }
    }

    pub async fn load(
        &self,
        filename: &PathBuf,
    ) -> anyhow::Result<()> {
        const HOSTS_EXAMPLE: &'static str = "   two examples of hosts.txt that is: 142.250.189.206 ipv4.google.com | 2607:f8b0:4005:814::200e ipv6.google.com   ";

        let mut file: String =
            smol::fs::read_to_string(filename)
                .await
                .context(
                    "cannot read from hosts.txt file",
                )
                .log_warn()?;

        // compatible Unix/Linux LF, Windows CR LF, and Mac CR
        // LF    = \n
        // CR LF = \r\n
        // CR    = \r
        while file.contains("\r") {
            file = file.replace("\r", "\n");
        }
        while file.contains("\n\n") {
            file = file.replace("\n\n", "\n");
        }

        // debug checks
        assert_eq!(file.contains("\r\n"), false);
        assert_eq!(file.contains("\r"), false);
        assert_eq!(file.contains("\n\n"), false);

        let mut lines = 0;
        for line in file.split("\n") {
            lines += 1;

            let mut line = line.to_string();
            // convert all Tab character to space
            while line.contains("\t") {
                line = line.replace("\t", " ");
            }

            // ignore comments.
            if !line.contains(" ") {
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
                log::warn!("Hosts: {filename:?}: ignore invalid line: no space character found at line {lines}. / {HOSTS_EXAMPLE}");
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
            if !domain.ends_with(".") {
                domain.push('.');
            }
            let domain = domain.to_ascii_lowercase();

            // any words following the first and last word, expect these is comments.
            if words.len() > 2 {
                log::debug!("Hosts: {filename:?}: ignore tailing words of line {lines}.");
            }

            // Entry
            self.map.entry_async(domain).await
            .or_insert_with(|| { Vec::new() })
            .get_mut()
            // Vec
            .push(ip);
        }

        log::info!("Hosts: total {lines} lines loaded, {} domain names loaded. mapping: {:#?}", self.map.len(), &self.map);

        Ok(())
    }

    pub async fn lookup(
        &self,
        domain: impl ToString,
    ) -> Option<Vec<IpAddr>> {
        let mut domain: String = domain.to_string();
        if !domain.ends_with(".") {
            domain.push('.');
        }
        let domain = domain.to_ascii_lowercase();

        match self.map.get_async(&domain).await {
            Some(entry) => Some(entry.get().clone()),
            None => None,
        }
    }

    fn _reqwest_resolve(
        &self,
        domain: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let maybe_ips =
                HOSTS.lookup(domain.as_str()).await;

            if let Some(ips) = maybe_ips {
                let addrs: Vec<SocketAddr> = {
                    // this is a stupid design by reqwest developers
                    // they said "Since the DNS protocol has no notion of ports, ... any port in the overridden addr will be ignored and traffic sent to the conventional port for the given scheme (e.g. 80 for http)."
                    // so why this API does not accept Vec<IpAddr> as argument type instead of Vec<SocketAddr> ?!
                    // alao the same problem exists at reqwest::ClientBuilder::resolve method
                    //
                    // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve_to_addrs
                    // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve

                    let mut x = vec![];
                    for ip in ips.iter() {
                        x.push(SocketAddr::new(*ip, 0));
                    }
                    x
                };
                let ok: Box<
                    dyn Iterator<Item = SocketAddr>
                        + Send,
                > = Box::new(addrs.into_iter());
                Ok(ok)
            } else {
                let msg = format!("DNS static resolve failed: unable to find a mapping from {domain:?} to IPv4/IPv6 addresses.");
                log::warn!("{}", &msg);
                let err: Box<
                    dyn std::error::Error + Send + Sync,
                > = Box::new(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    msg,
                ));
                Err(err)
            }
        })
    }
}

impl reqwest::dns::Resolve for Hosts {
    fn resolve(
        &self,
        domain: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        self._reqwest_resolve(domain)
    }
}
impl reqwest::dns::Resolve for &Hosts {
    fn resolve(
        &self,
        domain: reqwest::dns::Name,
    ) -> reqwest::dns::Resolving {
        self._reqwest_resolve(domain)
    }
}
