use crate::*;

/* ========== DNS Query ========= */

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DNSQuery {
    /// raw query domain name, String encoded by UTF-8
    pub name: String,

    /// raw query dns class, unsigned 16-bit integer
    pub rdclass: u16,

    /// raw query record type, unsigned 16-bit integer
    pub rdtype: u16,
}

impl core::fmt::Debug for DNSQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter)
        -> Result<(), core::fmt::Error>
    {
        f.write_str(
            format!("DNS-Query( {self} )").as_str()
        )
    }
}

impl core::fmt::Display for DNSQuery {
    fn fmt(&self, f: &mut core::fmt::Formatter)
        -> Result<(), core::fmt::Error>
    {
        let query: dns::Query =
            self.try_into()
            .expect("cannot convert to hickory Query");

        f.write_str(
            format!(
                "{} {}({}) {}({})",
                query.name().to_ascii(),
                query.query_class(), self.rdclass,
                query.query_type(), self.rdtype,
            ).as_str()
        )
    }
}
impl TryFrom<&str> for DNSQuery {
    type Error = anyhow::Error;
    fn try_from(val: &str) -> anyhow::Result<DNSQuery> {
        let mut val = val.to_string();
        while val.contains("  ") {
            val = val.replace("  ", " ");
        }

        let arr: Vec<&str> = val.split(" ").collect();
        if arr.len() != 3 {
            anyhow::bail!("malformed text format of dns query");
        }

        let mut name = arr[0].to_lowercase();
        if ! name.ends_with(".") {
            name.push('.');
        }
        let name: String =
            dns::Name::from_ascii(&name)?.to_utf8();

        let rdclass: u16 =
            arr[1]
            .replace(")", "")
            .split("(").last()
            .ok_or(anyhow::anyhow!("malformed rdclass field of dns query"))?
            .parse()?;

        let rdtype: u16 =
            arr[2]
            .replace(")", "")
            .split("(").last()
            .ok_or(anyhow::anyhow!("malformed rdtype field of dns query"))?
            .parse()?;

        Ok(DNSQuery { name, rdclass, rdtype })
    }
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
            val.name().to_string().to_lowercase();

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
        let mut name = val.name.to_string().to_lowercase();
        if ! name.ends_with(".") {
            name.push('.');
        }

        Ok(
            dns::Query::new()
            .set_name(dns::Name::from_utf8(name)?)
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DNSEntry {
    pub query: DNSQuery,
    pub response: Vec<u8>,
    pub expire: SystemTime,
    pub upstream: String,
    pub elapsed: Duration,
}
impl DNSEntry {
    fn _quoted_printable_opt() -> quoted_printable::Options
    {
        quoted_printable::Options::default()
        // do not split lines for each 76 characters 
        .line_length_limit(usize::MAX)

        // encodes CR LF as \r\n (not =0D=0A)
        .input_mode(quoted_printable::InputMode::Text)

        // report any malformed errors
        .parse_mode(quoted_printable::ParseMode::Strict)
    }

    pub fn to_json(&self) -> serde_json::Value {
        let resp_quoted: String =
            quoted_printable::encode_with_options(
                &self.response,
                Self::_quoted_printable_opt()
            );

        let expire_unix: String =
            self.expire
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs().to_string();

        let upstream_str: String =
            self.upstream.clone();

        let elapsed_secs: String =
            self.elapsed.as_secs_f64().to_string();

        serde_json::json!({
            "query": format!("{}", &self.query),
            "response": resp_quoted,
            "expire": expire_unix,
            "upstream": upstream_str,
            "elapsed": elapsed_secs,
        })
    }

    pub fn from_json(json: &serde_json::Value)
        -> anyhow::Result<Self>
    {
        let map =
            match json.as_object() {
                Some(v) => v,
                None => {
                    anyhow::bail!("DNSEntry::from_json() unexpected non-Object type of JSON data");
                }
            };

        macro_rules! map_get_str {
            ( $x:expr ) => {
                match map.get($x) {
                    Some(v) => {
                        if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            anyhow::bail!("DNSEntry::from_json() unexpected JSON field '.{}' is not String", $x);
                        }
                    },
                    None => {
                        anyhow::bail!("DNSEntry::from_json() unexpected JSON data without '.{}' field", $x);
                    }
                } // match map.get
            }
        }

        let query_text: String = map_get_str!("query");
        let resp_quoted: String = map_get_str!("response");
        let expire_unix: String = map_get_str!("expire");
        let upstream: String = map_get_str!("upstream");
        let elapsed_str: String = map_get_str!("elapsed");

        let query: DNSQuery =
            query_text.as_str()
            .try_into()?;

        let response: Vec<u8> =
            quoted_printable::decode_with_options(
                resp_quoted,
                Self::_quoted_printable_opt()
            )?;

        let expire: SystemTime = {
            let since = 
                if expire_unix.contains(".") {
                    let ts: f64 =
                        expire_unix.parse().unwrap_or(0.0);

                    Duration::from_secs_f64(ts)
                } else {
                    let ts: u64 =
                        expire_unix.parse().unwrap_or(0);

                    Duration::from_secs(ts)
                };

            SystemTime::UNIX_EPOCH
                .checked_add(since)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        };

        let elapsed: Duration = {
            let secs: f64 =
                elapsed_str.parse().unwrap_or(0.0);

            Duration::from_secs_f64(secs)
        };

        Ok(Self {
            query, response,
            expire,
            upstream, elapsed,
        })
    }
}

impl core::fmt::Debug for DNSEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter)
        -> Result<(), core::fmt::Error>
    {
        f.debug_struct("DNS-Entry")
            .field("query", &self.query)
            .field("response",
                &Bytes::copy_from_slice(&self.response)
            )
            .field("expire", &self.expire)
            .field("upstream", &self.upstream)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

impl TryFrom<&DNSEntry> for dns::Message {
    type Error = anyhow::Error;
    fn try_from(entry: &DNSEntry) -> anyhow::Result<dns::Message> {
        Ok(dns::Message::from_vec(&entry.response)?)
    }
}

/* ========== DNS Metrics ========== */
#[derive(Clone)]
pub struct DNSMetrics {
    latency: VecDeque<Duration>,
    reliability: u8, // 0% - 100%
    online: bool,
    last_respond: SystemTime,
    upstream: String,
}
impl core::fmt::Debug for DNSMetrics {
    fn fmt(&self, f: &mut core::fmt::Formatter)
        -> Result<(), core::fmt::Error>
    {
        f.debug_struct("DNS-Metrics")
            .field("latency", &self.latency())
            .field("reliability", &self.reliability)
            .field("online", &self.online)
            .field("last_respond", &self.last_respond)
            .field("upstream", &self.upstream)
            .finish()
    }
}

impl DNSMetrics {
    pub(crate) fn from(upstream: impl ToString) -> Self {
        Self {
            latency: VecDeque::new(),
            reliability: 50,
            online: false,
            last_respond: SystemTime::UNIX_EPOCH,
            upstream: upstream.to_string(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "latency":
                self.latency()
                .as_secs_f64()
                .to_string(),

            "reliability": self.reliability,
            "online": self.online,
            "last_respond":
                self.last_respond
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs_f64()
                .to_string(),

            "upstream": self.upstream.clone(),
        })
    }

    /// record a server works normal (on DNS query success)
    pub fn up(&mut self, elapsed: Duration) {
        self.online = true;

        if self.reliability < 100 {
            self.reliability += 1;
        }

        self._add_latency(elapsed);
        self.last_respond = SystemTime::now();
    }

    /// record a server down (on DNS query fails)
    pub fn down(&mut self) {
        self.online = false;

        if self.reliability > 0 {
            self.reliability -= 1;
        }

        self._add_latency(Duration::from_secs(999));
    }

    fn _add_latency(&mut self, elapsed: Duration) {
        self.latency.push_back(elapsed);

        while self.latency.len() > 100 {
            self.latency.pop_front();
        }
    }

    /* == Getters == */
    /// returns Average Latency
    pub fn latency(&self) -> Duration {
        let nanos: Vec<u128> =
            self.latency.iter()
            .map(|x|{ x.as_nanos() })
            .collect();

        let avg: u128 = average(&nanos);

        let avg: u64 = if avg > (u64::MAX as u128) {
            log::error!("latency great-than u64::MAX !!!");
            u64::MAX
        } else {
            avg as u64
        };

        Duration::from_nanos(avg)
    }

    pub fn reliability(&self) -> u8 {
        self.reliability
    }

    pub fn online(&self) -> bool {
        self.online
    }

    pub fn last_respond(&self) -> SystemTime {
        self.last_respond
    }

    pub fn upstream(&self) -> String {
        self.upstream.clone()
    }
}

/* DNS Resolver Array */
#[derive(Debug, Clone)]
pub struct DNSResolverArray {
    pub(crate) list: Arc<Vec<Arc<dyn DNSResolver>>>,
}

impl DNSResolverArray {
    // constructor
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

            /*
            // ignore any offline resolvers
            if my_metrics.reliability() <= 40 {
                continue;
            }
            */

            let resolver = resolver.clone();
            if best.is_none() {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
                continue;
            }

            let bm = best_metrics.clone().unwrap();

            let my_avg = my_metrics.latency();
            let best_avg = bm.latency();

            if my_avg < best_avg {
                best = Some( resolver.clone() );
                best_metrics = Some( my_metrics.clone() );
            }
            // Reliability seems to be more important than Latency
            if my_metrics.reliability() > bm.reliability()
            {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
            }
        }

        if let Some(resolver) = best {
            log::debug!("selected best resolver {:?}", &resolver);

            log::trace!("best_metrics: {best_metrics:?}");
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

