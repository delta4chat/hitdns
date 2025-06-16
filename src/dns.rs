//! this just re-export from hickory-proto.

pub use hickory_proto::{
    op::*,
    rr::{
        IntoName,
        domain::Name,
        LowerName,
        RecordData,
        dns_class::DNSClass,
        record_type::RecordType,
        record_data::RData,
        //dnssec::rdata::key::{KeyTrust, KeyUsage},
        rdata,
        Record,
    },
    serialize::binary::{BinEncodable, BinDecodable, BinEncoder},
};

/// RdClass
pub type RdClass = DNSClass;

/// RdType
pub type RdType = RecordType;

