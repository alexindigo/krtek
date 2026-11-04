//! Optional capture-owned VPN ingress. No daemon lock or physical watcher reentry.
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
    capture_network::{CaptureNetworkFeed, CaptureNetworkObservation},
};

static NEXT: AtomicI64 = AtomicI64::new(1);
static ACTIVE: Mutex<Option<Weak<CaptureNetworkFeed>>> = Mutex::new(None);

pub fn new_feed() -> Arc<CaptureNetworkFeed> {
    let id = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .unwrap_or(0);
    CaptureNetworkFeed::new(id)
}

pub struct CaptureNetworkRegistration {
    jvm: Arc<jnix::jni::JavaVM>,
    service: GlobalRef,
    feed: Arc<CaptureNetworkFeed>,
}

impl fmt::Debug for CaptureNetworkRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureNetworkRegistration")
            .finish_non_exhaustive()
    }
}

impl CaptureNetworkRegistration {
    pub fn attach(env: &JnixEnv<'_>, context: &AndroidContext) -> Self {
        let registration = Self {
            jvm: context.jvm.clone(),
            service: context.vpn_service.clone(),
            feed: context.capture_network.clone(),
        };
        *ACTIVE.lock().expect("capture registration") = Some(Arc::downgrade(&registration.feed));
        if !registration.feed.register(|id| {
            env.preload_classes(crate::classes::CAPTURE_NETWORK_CLASSES.iter().copied());
            env.call_method(
                registration.service.as_obj(),
                "attachCaptureNetwork",
                "(J)Z",
                &[JValue::Long(id)],
            )
            .and_then(|v| v.z())
        }) {
            let _ = env.exception_clear();
            *ACTIVE.lock().expect("capture registration") = None;
            log::warn!("Capture network registration unavailable; continuing daemon startup");
        }
        registration
    }
}

impl Drop for CaptureNetworkRegistration {
    fn drop(&mut self) {
        self.feed.close();
        let mut active = ACTIVE.lock().expect("capture registration");
        if active
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|feed| Arc::ptr_eq(&feed, &self.feed))
        {
            *active = None;
        }
        drop(active);
        if let Ok(env) = self.jvm.attach_current_thread_as_daemon() {
            if env
                .call_method(
                    self.service.as_obj(),
                    "detachCaptureNetwork",
                    "(J)Z",
                    &[JValue::Long(self.feed.registration())],
                )
                .and_then(|v| v.z())
                .is_err()
            {
                let _ = env.exception_clear();
                log::warn!("Capture network detach unavailable");
            }
        } else {
            log::warn!("Capture network detach thread unavailable");
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_net_mullvad_talpid_LocalCaptureNetworkBridge_published(
    env: JNIEnv<'_>,
    _: JClass<'_>,
    registration: jlong,
    generation: jlong,
    observation: JObject<'_>,
) {
    let feed = ACTIVE
        .lock()
        .expect("capture registration")
        .as_ref()
        .and_then(Weak::upgrade);
    let Some(feed) = feed.filter(|feed| feed.registration() == registration) else {
        return;
    };
    let env = JnixEnv::from(env);
    // Derived field conversion can panic on Java/native coupling errors. Close
    // only capture readiness; never unwind across JNI or kill physical eligibility.
    if catch_unwind(AssertUnwindSafe(|| {
        let observation = CaptureNetworkObservation::from_java(&env, observation);
        feed.publish(registration, generation, observation);
    }))
    .is_err()
    {
        feed.close();
        let _ = env.exception_clear();
        log::warn!("Capture network conversion unavailable");
    }
}
