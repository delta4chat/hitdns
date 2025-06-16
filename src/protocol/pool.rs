use crate::{
    *,
    util::*,
};

// A = Address
// C = Connection

#[derive(Debug)]
pub struct ConnManager<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    /// establish new connection.
    pub connect: fn(&A)->PinFut<std::io::Result<C>>,

    /// checks whether the provided connection has been closed?
    pub is_closed: fn(&mut C)->bool,
}

#[derive(Debug)]
pub struct ConnPoolInner<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    running: AtomicBool,
    protocol: String,

    remote: A,
    manager: ConnManager<A, C>,

    conns: scc::Stack<sdd::Shared<OnceGetter<C>>>,

    // because conns.len() is O(n), so maintain length metadata here for almost O(1) access.
    conns_len: AtomicUsize,

    conns_min: AtomicUsize,
}

#[derive(Debug)]
pub struct ConnPool<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    inner: Arc<ConnPoolInner<A, C>>,
}

impl<A, C> Clone for ConnPool<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<A, C> Deref for ConnPool<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    type Target = ConnPoolInner<A, C>;

    fn deref(&self) -> &ConnPoolInner<A, C> {
        &(self.inner)
    }
}

impl<A, C> ConnPool<A, C>
where
    A: fmt::Debug,
    C: 'static,
{
    pub const MIN_CONNS: usize = 1;

    pub fn new(protocol: &str, remote: A, manager: ConnManager<A, C>) -> Self {
        Self {
            inner:
                Arc::new(ConnPoolInner {
                    running: AtomicBool::new(false),
                    protocol: protocol.to_string(),

                    remote,
                    manager,

                    conns: Default::default(),
                    conns_len: AtomicUsize::new(0),
                    conns_min: AtomicUsize::new(1),
                }),
        }
    }

    pub fn protocol<'a>(&'a self) -> &'a str {
        self.protocol.as_str()
    }

    pub fn remote<'a>(&'a self) -> &'a A {
        &(self.remote)
    }

    pub fn conns_len(&self) -> usize {
        self.conns_len.load(Relaxed)
    }

    pub fn min_conns(&self) -> usize {
        self.conns_min.load(Relaxed)
    }

    pub fn set_min_conns(&self, min: usize) -> bool {
        if min < Self::MIN_CONNS {
            return false;
        }
        self.conns_min.store(min, Relaxed);
        true
    }

    /// add connection to pool.
    pub fn add_conn(&self, conn: C) -> sdd::Shared<OnceGetter<C>> {
        let conn = sdd::Shared::new(OnceGetter::new(conn));
        self.conns.push(conn.clone());
        self.conns_len.checked_add(1);
        conn
    }

    /// try to get connection from pool.
    /// * returned connection will be removed from pool to ensure no others to access it.
    pub fn pop_conn(&self) -> Option<C> {
        while let Some(getter) = self.conns.pop() {
            if let Some(conn) = getter.get() {
                self.conns_len.checked_sub(1);
                return Some(conn);
            }
        }
        None
    }

    /// get connection from pool, or start new connection if no connection avaliable in pool.
    pub async fn get_or_connect(&self) -> std::io::Result<C> {
        if let Some(entry) = self.pop_conn() {
            return Ok(entry);
        }

        (self.manager.connect)(self.remote()).await
    }

    pub async fn run(&self) -> std::io::Result<()> {
        if self.running.compare_exchange(false, true, Relaxed, Relaxed).is_err() {
            return Err(
                std::io::Error::new(
                    std::io::ErrorKind::ResourceBusy,
                    "only single ConnPool::run() main loop can be run in same time!",
                )
            );
        }
        let _defer = asyncute::Defer::new(|| {
            self.running.store(false, Relaxed);
        });

        let conn_timeout = Duration::from_secs(10);
        let conn_success_wait = Duration::from_secs(3);
        let conn_failed_wait = Duration::from_secs(5);
        let interval = Duration::from_secs(5);

        let mut maybe_ret;
        let mut zzz;

        let conn_checker =
            |maybe_conn: &mut Option<C>| {
                // Some(false) = conn exists and active open: no problem.
                // Some(true)  = conn exists and has been closed: should update conns_len.
                // None        = conn not found: should not update conns_len repeatedly.
                if maybe_conn.as_mut().map(self.manager.is_closed) == Some(true) {
                    maybe_conn.take();
                    self.conns_len.checked_sub(1);
                }
            };

        loop {
            // remove invalid connections.
            {
                let guard = scc::ebr::Guard::new();
                for getter in self.conns.iter(&guard) {
                    getter.with(conn_checker);
                }
            }

            // maintain minimum idle connections.
            zzz = true;
            while self.conns_len() < self.min_conns() {
                zzz = false;

                maybe_ret = (self.manager.connect)(self.remote()).timeout(conn_timeout).await;

                if let Some(ret) = maybe_ret {
                    match ret {
                        Ok(conn) => {
                            self.add_conn(conn);
                            async_io::Timer::after(conn_success_wait).await;
                        },
                        Err(e) => {
                            log::warn!(
                                "failed to establish connection to '{:?}': error={:?}",
                                self.remote(), e,
                            );
                            async_io::Timer::after(conn_failed_wait).await;
                        }
                    }
                } else {
                    log::warn!("failed to establish connection to '{:?}': timed out!", self.remote());
                }
            }
            if zzz {
                async_io::Timer::after(interval).await;
            }
        }
    }
}
