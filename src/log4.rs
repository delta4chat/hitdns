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

pub fn my_filter() -> impl log4rs::filter::Filter {
    use log4rs::filter::{Filter, Response};
    use log::Record;

    #[derive(Debug)]
    struct MyFilter;

    impl Filter for MyFilter {
        fn filter(&self, rec: &Record) -> Response {
            let cfg = config::LoggerConfig::global();

            let log_self = cfg.always_log_self();
            let nolog_lib = ! cfg.log_extern_libs();

            if log_self || nolog_lib {
                let is_self = {
                    rec.target().contains("hitdns")
                    ||
                    if let Some(m)=rec.module_path(){
                        m.contains("hitdns")
                    } else {
                        false
                    }
                };

                if log_self && is_self {
                    return Response::Accept;
                }
                if nolog_lib {
                    if ! is_self {
                        return Response::Reject;
                    }
                }
            }

            if rec.level() <= cfg.level() {
                Response::Accept
            } else {
                Response::Reject
            }
        }
    }

    MyFilter
}

pub fn my_encoder() -> PatternEncoder {
    PatternEncoder::new("{date(%Y-%m-%d %H:%M:%S %Z)(utc)} {highlight([{level}])} |{thread}| (({module}:{line})) {message}\n") // use Unix LF newline for all platforms
}

pub fn stderr_appender() -> ConsoleAppender {
    ConsoleAppender::builder()
    .encoder(Box::new(my_encoder()))
    .target(Stderr)
    .build()
}

pub fn disk_rolling_policy() -> CompoundPolicy {
    CompoundPolicy::new(
        // maximum single file size: 5.0 MB
        Box::new(SizeTrigger::new(1024*1024*5)),

        // * hitdns.2.log.gz
        // * hitdns.3.log.gz
        // * hitdns.4.log.gz
        // * etc...
        //
        // maximum total file size: 95.0 MB
        // maximum 19 files
        Box::new(
            FixedWindowRoller::builder()
            .base(2)
            .build(disk_filename_gzip().as_path().to_str().expect("unable to convert path to str"), 20)
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

pub fn log4rs_config() -> log4rs::Config {
    log4rs::Config::builder()
    .appender(
        Appender::builder()
        .filter(Box::new(my_filter()))
        .build("stderr", Box::new(stderr_appender()))
    )
    .appender(
        Appender::builder()
        .filter(Box::new(my_filter()))
        .build("disk", Box::new(disk_appender()))
    )
    .build(
        RootLogger::builder()
        .appender("stderr")
        .appender("disk")
        // filtered by function-based filter
        .build(log::LevelFilter::Trace)
    ).expect("unable to build log4rs::Config!")

}

static HANDLE: Lazy<log4rs::Handle> =
    Lazy::new(|| {
        log4rs::init_config(log4rs_config())
        .expect("unable to set global logger")
    });

pub fn log4rs_handle() -> &'static log4rs::Handle {
    &*HANDLE
}

pub fn setup() {
    let _ = log4rs_handle();
}
