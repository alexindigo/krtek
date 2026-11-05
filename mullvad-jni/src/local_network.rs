//! The optional watcher lifecycle. Neither publication nor detach takes DAEMON_CONTEXT.
use jnix::{
    FromJava, JnixEnv,
    jni::{
        JNIEnv,
        objects::{GlobalRef, JClass, JObject, JValue},
        sys::jlong,
    },
};
use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicI64, Ordering},
    },
};
use talpid_types::{
    android::AndroidContext,
    local_network::{LocalNetworkFeed, LocalNetworkSnapshot},
};

static NEXT_REGISTRATION: AtomicI64 = AtomicI64::new(1);
static ACTIVE: Mutex<Option<Weak<LocalNetworkFeed>>> = Mutex::new(None);

pub fn new_feed() -> Arc<LocalNetworkFeed> {
    let id = NEXT_REGISTRATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .unwrap_or(0);
    LocalNetworkFeed::new(id)
}

pub struct LocalNetworkRegistration {
    jvm: Arc<jnix::jni::JavaVM>,
    service: GlobalRef,
    feed: Arc<LocalNetworkFeed>,
}

impl fmt::Debug for LocalNetworkRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetworkRegistration")
            .finish_non_exhaustive()
    }
}

impl LocalNetworkRegistration {
    /// This optional feature always returns a lifecycle handle, including on attach failure.
    pub fn attach(env: &JnixEnv<'_>, context: &AndroidContext) -> Self {
        let registration = Self {
            jvm: context.jvm.clone(),
            service: context.vpn_service.clone(),
            feed: context.local_network.clone(),
        };
        *ACTIVE.lock().unwrap() = Some(Arc::downgrade(&registration.feed));
        let attached = registration.feed.register(|id| {
            // Keep optional classes out of the daemon's mandatory class preload.
            env.preload_classes(crate::classes::LOCAL_NETWORK_CLASSES.iter().copied());
            env.call_method(
                registration.service.as_obj(),
                "attachLocalNetwork",
                "(J)Z",
                &[JValue::Long(id)],
            )
            .and_then(|value| value.z())
        });
        if !attached {
            let _ = env.exception_clear();
            *ACTIVE.lock().unwrap() = None;
            log::warn!("Local network watcher registration unavailable; continuing daemon startup");
        }
        registration
    }
}

impl Drop for LocalNetworkRegistration {
    fn drop(&mut self) {
        self.feed.close();
        let mut active = ACTIVE.lock().unwrap();
        if active
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|feed| feed.registration() == self.feed.registration())
        {
            *active = None;
        }
        drop(active);
        if let Ok(env) = self.jvm.attach_current_thread_as_daemon() {
            if env
                .call_method(
                    self.service.as_obj(),
                    "detachLocalNetwork",
                    "(J)Z",
                    &[JValue::Long(self.feed.registration())],
                )
                .and_then(|value| value.z())
                .is_err()
            {
                let _ = env.exception_clear();
                log::warn!("Local network watcher detach unavailable");
            }
        } else {
            log::warn!("Local network watcher detach thread unavailable");
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_net_mullvad_talpid_LocalNetworkBridge_published(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    registration: jlong,
    snapshot: JObject<'_>,
) {
    let feed = ACTIVE.lock().unwrap().as_ref().and_then(Weak::upgrade);
    let Some(feed) =
        feed.filter(|feed| feed.registration() == registration && !feed.latest().closed)
    else {
        return;
    };
    let env = JnixEnv::from(env);
    // jnix's derived getters panic on coupling failures. Never unwind across JNI.
    let observed = catch_unwind(AssertUnwindSafe(|| {
        LocalNetworkSnapshot::from_java(&env, snapshot)
    }));
    match observed {
        Ok(snapshot) => {
            let first = feed.latest().latest.is_none();
            let networks = snapshot.networks.len();
            let addresses: usize = snapshot
                .networks
                .iter()
                .map(|network| network.addresses.len())
                .sum();
            let routes: usize = snapshot
                .networks
                .iter()
                .map(|network| network.routes.len())
                .sum();
            if feed.publish(registration, snapshot) && first {
                log::debug!(
                    "First local network snapshot received: networks={networks}, addresses={addresses}, routes={routes}"
                );
            }
        }
        Err(_) => {
            feed.close();
            let _ = env.exception_clear();
            log::warn!("Local network snapshot conversion unavailable");
        }
    }
}
