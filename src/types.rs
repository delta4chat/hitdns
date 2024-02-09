use crate::*;

/* ========== DNS Query ========= */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DNSQuery {
    pub name: String,
    pub rdclass: u16,
    pub rdtype: u16,
}

impl TryFrom<dns::Message> for DNSQuery {
    type Error = anyhow::Error;
    fn try_from(msg: dns::Message) -> anyhow::Result<Self> {
        if msg.message_type() != dns::MessageType::Query {
            anyhow::bail!("unexpected receive a non-query DNS message: {msg:?}");
        }

        let queries = msg.queries();
        let queries_len = queries.len();

        if queries_len == 0 {
            anyhow::bail!("unexpected DNS query message without any query section: {msg:?}");
        }

        // the best way to prevent the attacks of "try to fill large junk in DNS Server disk", that is, just keep first one query, and complete ignore "answers section" and "authority section" such as these field can store data that useless for query.
        if queries_len > 1 {
            log::debug!("unexpected DNS query message with multi queries, just keep the first query.");
        }
        if msg.name_servers().len() > 0 || msg.answers().len() > 0 {
            log::debug!("unexpected DNS query message with authority/answer section, ignore these sections.");
        }

        let query: dns::Query = queries[0].clone();
        Ok(query.into())
    }
}

impl From<dns::Query> for DNSQuery {
    fn from(val: dns::Query) -> DNSQuery {
        let mut name =
            val.name().to_string().to_ascii_lowercase();

        // de-duplicate by convert all domain to "ends with dot"
        if ! name.ends_with(".") {
            name.push('.');
        }

        DNSQuery {
            name,
            rdclass: val.query_class().into(),
            rdtype: val.query_type().into(),
        }
    }
}
impl TryFrom<&DNSQuery> for dns::Query {
    type Error = anyhow::Error;
    fn try_from(val: &DNSQuery)
        -> anyhow::Result<dns::Query>
    {
        use dns::IntoName;

        let mut name = val.name.to_string().to_ascii_lowercase();
        if ! name.ends_with(".") {
            name.push('.');
        }

        Ok(dns::Query::new()
            .set_name(name.into_name()?)
            .set_query_class(val.rdclass.into())
            .set_query_type(val.rdtype.into())
            .to_owned()
        )
    }
}

impl TryFrom<&DNSQuery> for dns::Message {
    type Error = anyhow::Error;
    fn try_from(val: &DNSQuery) -> anyhow::Result<dns::Message> {
        Ok(
            dns::Message::new()
            .set_id(0)
            .set_message_type(dns::MessageType::Query)
            .set_op_code(dns::OpCode::Query)
            .set_recursion_desired(true)
            .set_recursion_available(false)
            .set_authentic_data(false)
            .set_checking_disabled(false)
            .add_query(val.try_into()?)
            .to_owned()
        )
    }
}

/* ========== DNS Entry ========== */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DNSEntry {
    pub query: DNSQuery,
    pub response: Vec<u8>,
    pub expire: SystemTime,
    pub upstream: String,
    pub elapsed: Duration,
}

impl TryFrom<&DNSEntry> for dns::Message {
    type Error = anyhow::Error;
    fn try_from(entry: &DNSEntry) -> anyhow::Result<dns::Message> {
        Ok(dns::Message::from_vec(&entry.response)?)
    }
}

/* ========== DNS Metrics ========== */
#[derive(Debug, Clone)]
pub struct DNSMetrics {
    pub latency: Vec<Duration>,
    pub reliability: u8, // 0% - 100%
    pub online: bool,
    pub last_respond: SystemTime,
    pub upstream: String,
}

/* DNS Resolver Array */
#[derive(Debug, Clone)]
pub struct DNSResolverArray {
    pub(crate) list: Arc<Vec<Arc<dyn DNSResolver>>>,
}

impl DNSResolverArray {
    // constroctor
    pub fn from(
        val: impl IntoIterator<Item=Arc<dyn DNSResolver>>
    ) -> DNSResolverArray {
        let mut list = Vec::new();

        for resolver in val {
            list.push(resolver);
        }

        DNSResolverArray {
            list: Arc::new(list)
        }
    }

    /// select best resolver if available, or fallback to random.
    pub async fn best_or_random(&self)
        -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        if let Ok(v) = self.best().await {
            return Ok(v);
        }

        self.random()
    }

    /// select best resolver by minimum latency / maximum reliability.
    pub async fn best(&self)
        -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        let mut best = None;
        let mut best_metrics = None;
        for resolver in self.list.as_ref().iter() {
            let my_metrics = resolver.dns_metrics().await;

            // ignore any offline resolvers
            if my_metrics.reliability <= 40 {
                continue;
            }

            let resolver = resolver.clone();
            if best.is_none() {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
                continue;
            }

            let bm = best_metrics.clone().unwrap();

            let mut tmp: Vec<u128>;
            let metrics_avg = {
                tmp = my_metrics.latency.iter().map(
                    |x| { x.as_millis() }
                ).collect();

                average(&tmp)
            };   
            let best_avg = {
                tmp = bm.latency.iter().map(
                    |x| { x.as_millis() }
                ).collect();

                average(&tmp)
            };

            if metrics_avg < best_avg {
                best = Some( resolver.clone() );
                best_metrics = Some( my_metrics.clone() );
            }
            // Reliability seems to be more important than Latency
            if my_metrics.reliability > bm.reliability {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
            }
        }

        if let Some(resolver) = best {
            log::info!("selected best resolver {:?} with metrics {best_metrics:?}", &resolver);
            Ok(resolver)
        } else {
            anyhow::bail!("cannot select best resolver! maybe Internet offline, or empty list of resolvers")
        }
    }

    pub fn random(&self)
        -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        if self.list.is_empty() {
            anyhow::bail!("unexpected empty list of DNS Resolvers!");
        }

        for _ in 0..10 {
            // get newest length
            let len = self.list.len();

            let n = fastrand::usize(0..len);

            if let Some(resolver) = self.list.get(n) {
                return Ok( resolver.clone() );
            } else {
                log::debug!("unexpected cannot get({n}) from resolver list: maybe self.list.len()=={len} changed before get?");
            }
        }

        anyhow::bail!("cannot get resolver randomly")
    }

    /// select fixed one of all resolvers (often useless)
    pub fn fixed(&self) -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        if let Some(resolver) = self.list.get(0) {
            Ok( resolver.clone() )
        } else {
            anyhow::bail!("cannot select best resolver: empty list of resolvers!")
        }
    }
}

/*
impl DNSResolver for DNSResolverArray {
    fn dns_resolve(&self, query: &DNSQuery) ->DNSResolving{
        self.select_best().dns_resolve(query)
    }

    fn dns_upstream(&self) -> String {
    }

    fn dns_protocol(&self) -> &str {
    }
}
*/
