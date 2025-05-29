//! DNS Entry (response)

use crate::{
    *,
    query::*,
    upstream::*,
    helper::*,
};

/// the source of DNS Record.
/// * Internet: this record is from public DNS upstream.
/// * Hosts: this record is from some hosts.txt files located in system path or user-defined path.
/// * Local: this record is from router, gateway, or another kind of LAN domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DNSRecordSource {
    Internet(Arc<dyn DNSUpstream>),
    Hosts,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSEntry {
    /// whole DNS Response in wire format
    pub wire: Bytes,

    /// expire timestamp of this entry
    pub expire_time: SystemTime,

    /// this DNS record is from which source?
    pub source: DNSRecordSource,
}

