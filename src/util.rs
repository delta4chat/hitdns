#![forbid(unsafe_code)]

use crate::*;

use core::ops::{Deref, DerefMut, Range};

use portable_atomic::{*, Ordering::Relaxed};

pub trait AtomicType: fmt::Debug {
    type Atomic;
}

#[derive(Debug)]
pub struct Atomic<T: AtomicType>(T::Atomic);

macro_rules! atomic_impls {
    ($($t:ident = $atom:ident,)*) => {
        $(
            impl AtomicType for $t {
                type Atomic = $atom;
            }

            impl Atomic<$t> {
                pub const fn new(val: $t) -> Self {
                    Self::from_atomic($atom::new(val))
                }

                pub const fn from_atomic(atom: $atom) -> Self {
                    Self(atom)
                }

                pub const fn default() -> Self {
                    Self::new(false as $t)
                }
            }

            impl Deref for Atomic<$t> {
                type Target = $atom;
                fn deref(&self) -> &$atom {
                    &self.0
                }
            }

            impl DerefMut for Atomic<$t> {
                fn deref_mut(&mut self) -> &mut $atom {
                    &mut self.0
                }
            }

            impl From<$t> for Atomic<$t> {
                fn from(val: $t) -> Self {
                    Self::new(val)
                }
            }

            impl From<&Atomic<$t>> for $t {
                fn from(val: &Atomic<$t>) -> $t {
                    val.load(Relaxed)
                }
            }

            impl PartialEq for Atomic<$t> {
                fn eq(&self, other: &Self) -> bool {
                    self.load(Relaxed) == other.load(Relaxed)
                }
            }
            impl Eq for Atomic<$t> {}

            impl Hash for Atomic<$t> {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    self.load(Relaxed).hash(state)
                }
            }
        )*
    }
}

atomic_impls!(
    bool  = AtomicBool,

    u8    = AtomicU8,
    u16   = AtomicU16,
    u32   = AtomicU32,
    usize = AtomicUsize,
    u64   = AtomicU64,
    u128  = AtomicU128,

    i8    = AtomicI8,
    i16   = AtomicI16,
    i32   = AtomicI32,
    isize = AtomicIsize,
    i64   = AtomicI64,
    i128  = AtomicI128,
);

// TODO try replace lock to other things
/// a getter that only can get value once.
#[derive(Debug)]
pub struct OnceGetter<T> {
    empty: AtomicBool,
    inner: std::sync::Mutex<Option<T>>,
}

impl<T> OnceGetter<T> {
    pub const fn new(val: T) -> Self {
        Self {
            empty: AtomicBool::new(false),
            inner: std::sync::Mutex::new(Some(val)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.empty.load(Relaxed)
    }

    pub fn get(&self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        let mv = self.inner.lock().unwrap_or_else(|e| { e.into_inner() }).take();
        self.empty.store(true, Relaxed);

        mv
    }

    pub fn with<R, F>(&self, mut f: F) -> R
    where
        F: FnMut(&mut Option<T>) -> R,
    {
        if self.empty.load(Relaxed) {
            return f(&mut None);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| { e.into_inner() });
        let r = f(&mut *inner);

        if inner.is_none() {
            self.empty.store(true, Relaxed);
        }

        r
    }
}
