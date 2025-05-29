//! Hit DNS library for reusable functions (for example DNS Cache, DNS Query trait, Database load/store logic).

#![forbid(unsafe_code)]

#![warn(missing_docs)]

pub mod dns;
pub mod query;
pub mod upstream;

pub(crate) use core::fmt::Write;

pub(crate) fn err_invalid_input<T, M>(msg: M) -> std::io::Result<T>
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    Err(invalid_input(msg))
}

pub(crate) fn invalid_input<M>(msg: M) -> std::io::Error
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}
