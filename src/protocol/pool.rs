use crate::*;

// A = Address
// C = Connection
// F = Function for connecting (connector)

#[derive(Debug)]
pub struct ConnPoolInner<A, C, F>
where
    A: fmt::Debug,
    C: 'static,
    F: Fn(&A) -> PinFut<std::io::Result<C>>,
{
    running: AtomicBool,
    protocol: String,

    remote: A,
    connect: F,

    conns: scc::Stack<sdd::Shared<C>>,

    // because conns.len() is O(n), so maintain length metadata here for almost O(1) access.
    conns_len: AtomicUsize,

    conns_min: AtomicUsize,
}

#[derive(Debug)]
pub struct ConnPool<A, C, F>
where
    A: fmt::Debug,
    C: 'static,
    F: Fn(&A) -> PinFut<std::io::Result<C>>,
{
    inner: Arc<ConnPoolInner<A, C, F>>,
}

impl<A, C, F> Clone for ConnPool<A, C, F>
where
    A: fmt::Debug,
    C: 'static,
    F: Fn(&A) -> PinFut<std::io::Result<C>>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<A, C, F> Deref for ConnPool<A, C, F>
where
    A: fmt::Debug,
    C: 'static,
    F: Fn(&A) -> PinFut<std::io::Result<C>>,
{
    type Target = ConnPoolInner<A, C, F>;

    fn deref(&self) -> &ConnPoolInner<A, C, F> {
        &(self.inner)
    }
}

impl<A, C, F> ConnPool<A, C, F>
where
    A: fmt::Debug,
    C: 'static,
    F: Fn(&A) -> PinFut<std::io::Result<C>>,
{
    pub const MIN_CONNS: usize = 1;

    pub fn new(protocol: &str, remote: A, connect: F) -> Self {
        Self {
            inner:
                Arc::new(ConnPoolInner {
                    running: AtomicBool::new(false),
                    protocol: protocol.to_string(),

                    remote,
                    connect,

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
    pub fn add_conn(&self, conn: C) -> sdd::Shared<C> {
        let conn = sdd::Shared::new(conn);
        self.conns.push(conn.clone());
        self.conns_len.checked_add(1);
        conn
    }

    /// try to get connection from pool.
    /// * returned connection will be removed from pool to ensure no others to access it.
    pub fn pop_conn(&self) -> Option<sdd::Shared<C>> {
        if let Some(conn) = self.conns.pop() {
            self.conns_len.checked_sub(1);
            Some(conn.as_ref().as_ref().clone())
        } else {
            None
        }
    }

    /// get connection from pool, or start new connection if no connection avaliable in pool.
    pub async fn get_or_connect(&self) -> std::io::Result<sdd::Shared<C>> {
        if let Some(entry) = self.pop_conn() {
            return Ok(entry);
        }

        (self.connect)(self.remote()).await.map(sdd::Shared::new)
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

        let mut maybe_ret;
        loop {
            while self.conns_len() < self.min_conns() {
                maybe_ret = (self.connect)(self.remote()).timeout(conn_timeout).await;

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
        }
    }
}
