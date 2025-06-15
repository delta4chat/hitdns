//! Async wrapper of sled database.

use core::{
    any::Any,
    panic::AssertUnwindSafe,
    fmt::{self, Write},
    ops::Deref,
    task::{Poll, Context, Waker},
    future::Future,
    pin::Pin,
    time::Duration,
};

use std::{
    panic::catch_unwind,
    sync::Arc,
    path::Path,
};

use portable_atomic::{AtomicBool, Ordering::Relaxed};
use once_cell::sync::OnceCell;
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

pub trait WithDb: (FnOnce(&sled::Db) -> Res) + Send + 'static {}
impl<T: (FnOnce(&sled::Db) -> Res) + Send + 'static> WithDb for T {}

impl fmt::Debug for dyn WithDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dyn WithDb")
         .field("function", &"dyn FnOnce(&sled::Db) -> Box<dyn Any + Send>")
         .field("pointer", &{ self as *const _ })
         .finish()
    }
}

pub type BoxWithDb = Box<dyn WithDb>;

#[derive(Debug)]
pub struct SledOperation {
    /// performs sync operation to sled db by calling callback with reference to `sled::Db`.
    /// * it's API like to `std::thread::LocalKey::with`, but internal implementation is completely different.
    with_db: BoxWithDb,

    sw: SledWith,
}

impl SledOperation {
    pub fn new<F: WithDb>(f: F) -> Self {
        Self {
            with_db: Box::new(f),
            sw: SledWith::new(),
        }
    }
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
            let waker = sdd::Shared::new(ctx.waker().clone());
            loop {
                // compare exchange is not needed:
                // it just performs update waker if it already has value.
                self.waker.swap(
                    (Some(waker.clone()), sdd::Tag::None),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SledRunnerThreadStatus {
    /// total runner threads (include all threads that does not care whether running/exited/working/idle).
    pub total: Vec<u128>,

    /// how many runner threads is running?
    /// * this does not care whether it's working (by running sled operations)
    pub running: Vec<u128>,

    /// how many runner threads has been exited? (std::thread::JoinHandle::is_finished() == true)
    pub exited: Vec<u128>,

    /// how many runner thread is working? (doing sled operations)
    /// * in most of cases, if a thread is working, that is also means it's running.
    pub working: Vec<u128>,

    /// how many runner thread is idle? (waiting for incoming sled operations)
    /// * this does not includes any dead thread (exited/finished threads).
    pub idle: Vec<u128>,

    /// how many runner threads has been removed from index?
    pub remove: Vec<u128>,
}

impl SledRunnerThreadStatus {
    pub fn new(total_len: usize) -> Self {
        Self {
            total: Vec::with_capacity(total_len),

            running: Vec::with_capacity(total_len),
            exited: Vec::new(),

            working: Vec::new(),
            idle: Vec::new(),

            remove: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct SledRunnerThreadState {
    /// the ID of sled runner worker.
    id: u128,

    /// the unparker for unpacking the associated thread.
    unparker: parking::Unparker,

    /// shared join handle for associated thread.
    join_handle: OnceCell<std::thread::JoinHandle<()>>,

    /// whether the associated thread is working for handle sled operations?
    is_working: AtomicBool,

    /// request the associated thread to exit.
    please_exit: AtomicBool,
}

impl SledRunnerThreadState {
    pub fn is_running(&self) -> bool {
        ! self.join_handle.wait().is_finished()
    }

    pub fn is_working(&self) -> bool {
        self.is_working.load(Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct SledRunner {
    db: sled::Db,
    ops_tx: Sender<SledOperation>,
    ops_rx: Receiver<SledOperation>,
    threads: Arc<scc::HashIndex<u128, Arc<SledRunnerThreadState>>>,
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
    pub fn new<P: AsRef<Path>>(config: sled::Config) -> sled::Result<Self> {
        let db = config.open()?;
        Ok(Self::from(db))
    }

    /// easy method for simple open in-disk pathname.
    /// * path type is directory, it must not a file.
    /// * this does not support temporary storage.
    /// * automatically create directory if not exists.
    pub fn open<P: AsRef<Path>>(path: P) -> sled::Result<Self> {
        let db = sled_config().path(path).open()?;
        Ok(Self::from(db))
    }

    /// the main loop of SledRunner worker threads.
    fn run_loop(
        &self,
        state: Arc<SledRunnerThreadState>,
        parker: parking::Parker,
    ) {
        const FAIL_SLEEP_TIME: Duration = Duration::from_secs(3);

        let id = state.id;

        let _defer = asyncute::Defer::new(|| {
            self.threads.remove(&id);
        });

        let mut with_db;
        let mut sw;

        let mut res;
        let mut shared_res;

        loop {
            if state.please_exit.load(Relaxed) {
                break;
            }

            SledOperation { with_db, sw } =
                match self.ops_rx.recv_blocking() {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            "[async sled {}] failed to receive operations from channel!!! Error: {:?}",
                            id, e,
                        );
                        parker.park_timeout(FAIL_SLEEP_TIME);
                        continue;
                    }
                };

            res =
                // any user code's panic must be catched!
                // so force using AssertUnwindSafe even `self` and `sled::Db` both are non-UnwindSafe types.
                match catch_unwind(AssertUnwindSafe(|| { (with_db)(&self.db) })) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            "[async sled {}] panic from user provided code! Error: dyn Any = {:?}",
                            id, e,
                        );
                        continue;
                    }
                };
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
            core::mem::drop(shared_res);

            // if waker missed, it's no problem! because next `SledWith::poll()` will checks `self.res`.
            if let Some(shared_waker) = sw.waker.get_shared(Relaxed, &{ sdd::Guard::new() }) {
                shared_waker.wake_by_ref();
            }

            core::mem::drop(sw);
        }
    }

    /// spawn new thread for handle incoming `sled::Db` operations.
    pub async fn spawn_thread(&self) -> std::io::Result<Arc<SledRunnerThreadState>> {
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

        let state =
            Arc::new(SledRunnerThreadState {
                id,
                unparker,

                join_handle: OnceCell::new(),
                is_working: AtomicBool::new(false),

                please_exit: AtomicBool::new(false),
            });
        let this = self.clone();

        let jh = {
            let state = state.clone();

            std::thread::Builder::new()
            .name(format!("async-sled-{}", id as u64))
            .stack_size(1048576)
            .spawn(move || {
                this.run_loop(state, parker);
            })?
        };
        state.join_handle.set(jh).expect("bug: unexpectedly failed set join handle of sled runner thread!");

        if self.threads.insert_async(id, state.clone()).await.is_ok() {
            Ok(state)
        } else {
            Err(std::io::Error::other("id should be unique but duplicated!"))
        }
    }

    pub fn check(
        &self,
        allow_remove: bool,
    ) -> SledRunnerThreadStatus {
        let mut st =
            SledRunnerThreadStatus::new(
                // maximum possible number of values.
                self.threads.len()
            );

        let g = sdd::Guard::new();
        let mut id;
        for (id_, state) in self.threads.iter(&g) {
            if st.total.contains(id_) {
                continue;
            }
            id = *id_;

            st.total.push(id);

            if state.is_running() {
                st.running.push(id);
            } else {
                st.exited.push(id);
                if allow_remove {
                    st.remove.push(id);
                }
                continue;
            }

            if state.is_working() {
                st.working.push(id);
            } else {
                st.idle.push(id);
            }
        }
        core::mem::drop(g);

        if allow_remove {
            for rm_id in st.remove.iter() {
                self.threads.remove(rm_id);
            }
        }

        st
    }

    /// execute sync queries in sled database, and it's return value can be received in asynchronous context (this just a shortcut for `self.try_queue(SledOperation::new(f))`.
    /// * this never blocking.
    /// * see [`Self::try_queue()`].
    pub fn try_with<F: WithDb>(&self, f: F) -> core::result::Result<SledWith, SledOperation> {
        self.try_queue(SledOperation::new(f))
    }

    /// try to push provided [`SledOperation`] to wait queue.
    ///
    /// * this never blocking and will queue it to `async-channel`.
    /// * returns [`SledWith`] that implements [`Future`] so can be `.await` or poll manually.
    /// * if there is no space (channel full), return Err with [`SledOperation`]: this struct means "pending operation", it can be push back to wait queue using [`Self::queue()`]. it is fine if you discards `SledOperation`.
    /// # Panics
    /// it will panic if internal channel is closed unexpectedly.
    pub fn try_queue(&self, op: SledOperation) -> core::result::Result<SledWith, SledOperation> {
        let sw = op.sw.clone();
        match self.ops_tx.try_send(op) {
            Ok(_) => Ok(sw),
            Err(e) => {
                if e.is_closed() {
                    panic!("bug: unexpectedly operations channel closed!");
                }
                Err(e.into_inner())
            },
        }
    }

    /// execute sync queries in sled database, and it's return value can be received in asynchronous context (this just a shortcut for `self.queue(SledOperation::new(f)).await`.
    /// * see [`Self::queue()`].
    pub async fn with<F: WithDb>(&self, f: F) -> SledWith {
        self.queue(SledOperation::new(f)).await
    }

    /// to push provided [`SledOperation`] to wait queue.
    /// * returns [`SledWith`] that implements [`Future`] so can be `.await` or poll manually.
    /// # Panics
    /// it will panic if internal channel is closed unexpectedly.
    pub async fn queue(&self, op: SledOperation) -> SledWith {
        let sw = op.sw.clone();
        match self.ops_tx.send(op).await {
            Ok(_) => sw,
            Err(_) => { // async_channel::SendError just a wrapper of "op"...
                panic!("bug: unexpectedly operations channel closed!");
            },
        }
    }
}

