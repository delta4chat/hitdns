use crate::*;

pub use log4rs::{
    Logger,
    config::{
        Appender,
        Root as RootLogger,
    },
    encode::{
        Encode,
        pattern::PatternEncoder,
    },
    append::{
        console::{
            ConsoleAppender,
            Target::Stderr,
        },
        rolling_file::{
            RollingFileAppender,
            policy::compound::{
                CompoundPolicy,
                trigger::size::SizeTrigger,
                roll::{
                    fixed_window::FixedWindowRoller,
                },
            },
        },
    },
};

pub fn my_encoder() -> PatternEncoder {
    PatternEncoder::new("{date(%Y-%m-%d %H:%M:%S %Z)(utc)} {highlight([{level}])} |{thread}| (({module}:{line})) {message} {n}")
}

pub fn stderr_appender() -> ConsoleAppender {
    ConsoleAppender::builder()
    .encoder(Box::new(my_encoder()))
    .target(Stderr)
    .build()
}

pub fn disk_filename() -> PathBuf {
    let mut path = config::LOG_DIR.deref().clone();
    path.push("hitdns.log");
    path
}

pub fn disk_rolling_policy() -> CompoundPolicy {
    CompoundPolicy::new(
        // maximum single file size: 5.0 MB
        Box::new(SizeTrigger::new(1024*1024*5)),

        // * hitdns.log
        // * hitdns.2.log
        // * hitdns.3.log
        // * etc...
        //
        // maximum total file size: 95.0 MB
        // maximum 19 files
        Box::new(
            FixedWindowRoller::builder()
            .base(2)
            .build("hitdns.{}.log.gz", 20)
            .expect("unable build FixedWindowRoller")
        ),
    )
}

pub fn disk_appender() -> RollingFileAppender {
    RollingFileAppender::builder()
    .encoder(Box::new(my_encoder()))
    .append(true)
    .build(
        disk_filename(),
        Box::new(disk_rolling_policy()),
    ).expect("unable to build RollingFileAppender!")
}

pub fn log4rs_config(level: log::LevelFilter) -> log4rs::Config {
    log4rs::Config::builder()
    .appender(
        Appender::builder().build(
            "stderr",
            Box::new(stderr_appender()),
        )
    )
    .appender(
        Appender::builder().build(
            "disk",
            Box::new(disk_appender()),
        )
    )
    .build(
        RootLogger::builder()
        .appender("stderr")
        .appender("disk")
        .build(level)
    ).expect("unable to build log4rs::Config!")

}

pub static HANDLE: Lazy<log4rs::Handle> =
    Lazy::new(|| {
        log4rs::init_config(
            log4rs_config(log::LevelFilter::Debug)
        ).expect("unable to set global logger")
    });

