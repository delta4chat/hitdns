//! Async wrapper of sled database.

use core::{
    any::Any,
    fmt::Debug,
    ops::Deref,
    task::{Poll, Context, Waker},
    future::Future,
    pin::Pin,
    time::Duration,
};

use std::{
    sync::Arc,
    path::Path,
};

use portable_atomic::Ordering::Relaxed;

use async_channel::{Sender, Receiver};

pub fn sled_config() -> sled::Config {
    sled::Config::new()
        .cache_capacity(1024*1024*100)
        .mode(sled::Mode::HighThroughput)
        .use_compression(true)
        .compression_factor(22)
        .temporary(false)
        //.create_new(?)
        .print_profile_on_drop(false)
}

pub type Res = Box<dyn Any + Send>;

pub trait WithDb: Debug + (FnOnce(&sled::Db) -> Res) + Send + 'static {}

pub type BoxWithDb = Box<dyn WithDb>;

#[derive(Debug)]
pub struct SledOperation {
    /// performs sync operation to sled db by calling callback with reference to `sled::Db`.
    /// * it's API like to `std::thread::LocalKey::with`, but internal implementation is completely different.
    with_db: BoxWithDb,

    sw: SledWith,
}

impl Deref for SledOperation {
    type Target = SledWith;

    fn deref<'a>(&'a self) -> &'a SledWith {
        &(self.sw)
    }
}

#[derive(Debug)]
pub struct SledWith {
    /// the returned value of [`SledOperation::with_db`].
    res: sdd::AtomicShared<Res>,

    /// after this operation completed, the waker will be called, then wake the associated Future.
    waker: sdd::AtomicShared<Waker>,
}

impl Clone for SledWith {
    fn clone(&self) -> Self {
        Self {
            res: Clone::clone(&self.res),
            waker: Clone::clone(&self.waker),
        }
    }
}

impl SledWith {
    pub const fn new() -> Self {
        Self {
            res: sdd::AtomicShared::null(),
            waker: sdd::AtomicShared::null(),
        }
    }
}

impl Future for SledWith {
    type Output = sdd::Shared<Res>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // check whether operation completes.
        if let Some(shared) = self.res.get_shared(Relaxed, &{ sdd::Guard::new() }) {
            return Poll::Ready(shared);
        }

        // register waker.
        if self.waker.is_null(Relaxed) {
            let waker = ctx.waker();
            loop {
                // compare exchange is not needed:
                // it just performs update waker if it already has value.
                self.waker.swap(
                    (Some(sdd::Shared::new(waker.clone())), sdd::Tag::None),
                    Relaxed,
                );

                if ! self.waker.is_null(Relaxed) {
                    break;
                }
            }
        }

        Poll::Pending
    }
}

#[derive(Debug, Clone)]
pub struct SledRunner {
    db: sled::Db,
    ops_tx: Sender<SledOperation>,
    ops_rx: Receiver<SledOperation>,
    threads: Arc<scc::HashIndex<u128, (Arc<std::thread::JoinHandle<()>>, parking::Unparker)>>,
}

impl SledRunner {
    /// create new runner from exists sled::Db instance.
    pub fn from(db: sled::Db) -> Self {
        let (ops_tx, ops_rx) = async_channel::bounded(1048576 * 5);
        Self {
            db,
            ops_tx, ops_rx,
            threads: Default::default(),
        }
    }

    /// create new runner with provided config.
    /// * config must set path otherwise open failed.
    pub fn new<P: AsRef<Path>>(config: sled::Config) -> std::io::Result<Self> {
        let db = config.open()?;
        Ok(Self::from(db))
    }

    /// easy method for simple open in-disk pathname.
    /// * path type is directory, it must not a file.
    /// * this does not support temporary storage.
    /// * automatically create directory if not exists.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let db = sled_config().path(path).open()?;
        Ok(Self::from(db))
    }

    fn run_loop(&self, id: u128, parker: parking::Parker) {
        const FAIL_SLEEP_TIME: Duration = Duration::from_secs(3);

        let _defer = asyncute::Defer::new(|| {
            self.threads.remove(&id);
        });

        let mut with_db;
        let mut sw;

        let mut res;
        let mut shared_res;

        loop {
            SledOperation { with_db, sw } =
                match self.ops_rx.recv_blocking() {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            "[async sled {}] failed to receive operations from channel!!! error={:?}",
                            id, e,
                        );
                        parker.park_timeout(FAIL_SLEEP_TIME);
                        continue;
                    }
                };

            res = (with_db)(&self.db);
            shared_res = sdd::Shared::new(res);
            loop {
                sw.res.swap(
                    (Some(shared_res.clone()), sdd::Tag::None),
                    Relaxed,
                );
                if ! sw.res.is_null(Relaxed) {
                    break;
                }
            }

            // if waker missed, it's no problem! because next `SledWith::poll()` will checks `self.res`.
            if let Some(shared_waker) = sw.waker.get_shared(Relaxed, &{ sdd::Guard::new() }) {
                shared_waker.wake_by_ref();
            }

            core::mem::drop((sw, shared_res));
        }
    }

    pub fn spawn_thread(&self) -> std::io::Result<Arc<std::thread::JoinHandle<()>>> {
        static ID_COUNTER: asyncute::id::ID = asyncute::option_unwrap!(asyncute::id::ID::from_bytes(b"\xacSledFut"));

        let id =
            match ID_COUNTER.generate() {
                Some(v) => v,
                _ => {
                    return Err(std::io::Error::other("ID's 64-bit counter exhausted!"));
                }
            };

        let parker = parking::Parker::new();
        let unparker = parker.unparker();

        let this = self.clone();

        let jh = 
            std::thread::Builder::new()
            .name(format!("async-sled-{}", id as u64))
            .stack_size(1048576)
            .spawn(move || {
                this.run_loop(id, parker);
            })?;
        let jh = Arc::new(jh);

        if self.threads.insert(id, (jh.clone(), unparker)).is_ok() {
            Ok(jh)
        } else {
            Err(std::io::Error::other("id should be unique but duplicated!"))
        }
    }

    pub fn with<F: WithDb>(&self, f: F) -> Result<SledWith, SledOperation> {
        let sw = SledWith::new();
        let op = SledOperation {
            with_db: Box::new(f),
            sw: sw.clone(),
        };
        match self.ops_tx.send_blocking(op) {
            Ok(_) => Ok(sw),
            Err(e) => Err(e.0),
        }
    }
}

