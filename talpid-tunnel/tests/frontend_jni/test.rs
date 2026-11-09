//! Run by the task-owned builder JVM harness using this exact production module.
#[path = "../../src/tun_provider/android/local_network/descriptor.rs"]
mod descriptor;
#[path = "../../src/tun_provider/android/local_network/jni_call.rs"]
mod jni_call;
use jnix::jni::{
    InitArgsBuilder, JNIVersion, JavaVM,
    objects::{JObject, JValue},
};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::Mutex;

struct Diagnostics(Mutex<Vec<String>>);
static DIAGNOSTICS: Diagnostics = Diagnostics(Mutex::new(Vec::new()));
impl log::Log for Diagnostics {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        self.0.lock().unwrap().push(record.args().to_string());
    }
    fn flush(&self) {}
}

#[test]
fn handled_throw_then_succeed_keeps_ownership_and_clears_the_same_attached_thread() {
    log::set_logger(&DIAGNOSTICS).unwrap();
    log::set_max_level(log::LevelFilter::Warn);
    let classpath = format!(
        "-Djava.class.path={}",
        std::env::var("JNI_FIXTURE_CLASSES").unwrap()
    );
    let args = InitArgsBuilder::new()
        .version(JNIVersion::V8)
        .option("-Xcheck:jni")
        .option(&classpath)
        .build()
        .unwrap();
    let vm = JavaVM::new(args).unwrap();
    let env = vm.attach_current_thread_as_daemon().unwrap();
    let thread = std::thread::current().id();
    let pointer = env.get_native_interface();
    let service = env
        .new_object("net/mullvad/talpid/fixture/Frontend", "()V", &[])
        .unwrap();
    let routes = env
        .new_object_array(0, "java/lang/String", JObject::null())
        .unwrap();
    let name = env.new_string("tun7").unwrap();
    let open = || {
        jni_call::handled(&env, "openLocalFrontend", || {
            env.call_method(
                service,
                "openLocalFrontend",
                "(J[Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Long(11), JValue::Object(JObject::from(routes))],
            )
        })
    };
    let finish = || {
        jni_call::handled(&env, "finishLocalFrontend", || {
            env.call_method(service, "finishLocalFrontend", "(J)V", &[JValue::Long(11)])
        })
    };
    let bind = || {
        jni_call::handled(&env, "bindLocalFrontend", || {
            env.call_method(
                service,
                "bindLocalFrontend",
                "(JLjava/lang/String;)Z",
                &[JValue::Long(11), JValue::Object(JObject::from(name))],
            )
        })
    };
    let current = || env.get_field(service, "owned", "Z").unwrap().z().unwrap();
    open().unwrap();
    for (method, signature, argument) in [
        (
            "handoverLocalFrontend",
            "(JJ[Ljava/lang/String;)Ljava/lang/Object;",
            JObject::from(routes),
        ),
        (
            "handoverSecuredFrontend",
            "(JJLjava/lang/Object;)Ljava/lang/Object;",
            JObject::null(),
        ),
    ] {
        let handover = || {
            jni_call::handled(&env, method, || {
                env.call_method(
                    service,
                    method,
                    signature,
                    &[JValue::Long(11), JValue::Long(12), JValue::Object(argument)],
                )
            })
        };
        env.set_field(service, "failHandover", "Z", JValue::Bool(1))
            .unwrap();
        assert!(handover().is_err());
        assert!(!env.exception_check().unwrap());
        assert!(
            current(),
            "handover acknowledgement error released ownership"
        );
        env.set_field(service, "failHandover", "Z", JValue::Bool(0))
            .unwrap();
        handover().unwrap();
        assert_eq!(env.get_native_interface(), pointer);
    }
    env.set_field(service, "failUnregister", "Z", JValue::Bool(1))
        .unwrap();
    assert!(finish().is_err());
    assert!(!env.exception_check().unwrap());
    assert!(current(), "failed unregister lost the platform owner");
    env.set_field(service, "failUnregister", "Z", JValue::Bool(0))
        .unwrap();
    finish().unwrap();
    assert!(!current());
    assert_eq!(
        vm.attach_current_thread_as_daemon()
            .unwrap()
            .get_native_interface(),
        pointer
    );

    // Startup can allocate ownership before its own cleanup throws.
    env.set_field(service, "failOpen", "Z", JValue::Bool(1))
        .unwrap();
    env.set_field(service, "failUnregister", "Z", JValue::Bool(1))
        .unwrap();
    assert!(open().is_err());
    assert!(!env.exception_check().unwrap());
    assert!(current());
    env.set_field(service, "failUnregister", "Z", JValue::Bool(0))
        .unwrap();
    finish().unwrap();
    assert!(!current());
    env.set_field(service, "failOpen", "Z", JValue::Bool(0))
        .unwrap();
    open().unwrap();
    for mode in [1, 2] {
        env.set_field(service, "failBind", "I", JValue::Int(mode))
            .unwrap();
        assert!(bind().is_err());
        assert!(
            !env.exception_check().unwrap(),
            "handled bind retained a throwable"
        );
        assert!(current());
        env.set_field(service, "failBind", "I", JValue::Int(0))
            .unwrap();
        assert!(bind().unwrap().z().unwrap());
    }
    finish().unwrap();
    assert!(!current());
    assert!(!env.exception_check().unwrap());
    assert_eq!(std::thread::current().id(), thread);
    assert_eq!(env.get_native_interface(), pointer);
    descriptor_fault_matrix(&env);
    let logs = DIAGNOSTICS.0.lock().unwrap();
    assert!(
        logs.iter()
            .any(|line| line.contains("SecurityException: unregister capture callback"))
    );
    assert!(
        logs.iter()
            .any(|line| line.contains("diagnostic unavailable"))
    );
}

extern "system" fn close_fd(_: jnix::jni::JNIEnv<'_>, _: jnix::jni::objects::JClass<'_>, fd: i32) {
    // SAFETY: the fixture gives up its sole pending descriptor at this callback.
    drop(unsafe { std::fs::File::from_raw_fd(fd) });
}

fn descriptor_fault_matrix(env: &jnix::jni::JNIEnv<'_>) {
    env.register_native_methods(
        "net/mullvad/talpid/fixture/Frontend",
        &[jnix::jni::NativeMethod {
            name: "closeFd".into(),
            sig: "(I)V".into(),
            fn_ptr: close_fd as *mut std::ffi::c_void,
        }],
    )
    .unwrap();
    for mode in 0..=8 {
        let service = env.auto_local(
            env.new_object("net/mullvad/talpid/fixture/Frontend", "()V", &[])
                .unwrap(),
        );
        let (peer, socket) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let raw = socket.into_raw_fd();
        let outcome = jni_call::handled(env, "conversion handover", || {
            let result = env
                .call_method(
                    service.as_obj(),
                    "conversionHandover",
                    "(II)Lnet/mullvad/talpid/model/CaptureHandoverResult;",
                    &[JValue::Int(raw), JValue::Int(mode)],
                )
                .and_then(|value| value.l())
                .map_err(descriptor::DecodeError::from)?;
            let result = env.auto_local(result);
            descriptor::handover(
                env,
                service.as_obj(),
                12,
                result.as_obj(),
                |value| match descriptor::decode(env, value)? {
                    descriptor::OpenResult::Descriptor(fd) => Ok(fd),
                    _ => Err(descriptor::DecodeError::InvalidResult),
                },
                |error| error,
            )
        });
        assert!(
            !env.exception_check().unwrap(),
            "mode {mode}: throwable retained"
        );
        let live = || {
            // SAFETY: F_GETFD does not borrow or dereference this integer fd;
            // querying an already closed number is the expected negative oracle.
            unsafe { libc::fcntl(raw, libc::F_GETFD) != -1 }
        };
        let transfers = env
            .get_field(service.as_obj(), "transfers", "I")
            .unwrap()
            .i()
            .unwrap();
        if mode == 0 {
            let (fd, retained) = outcome.unwrap();
            let fd = fd.unwrap();
            assert!(!retained);
            assert!(live());
            assert_eq!(transfers, 1);
            jni_call::handled(env, "finish transferred", || {
                env.call_method(
                    service.as_obj(),
                    "finishLocalFrontend",
                    "(J)V",
                    &[JValue::Long(12)],
                )
            })
            .unwrap();
            assert!(live(), "finish closed a transferred descriptor");
            peer.send(b"still native-owned").unwrap();
            let socket = std::os::unix::net::UnixDatagram::from(fd);
            let mut bytes = [0; 32];
            let count = socket.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..count], b"still native-owned");
            drop(socket);
            assert!(!live());
        } else {
            assert!(
                outcome.is_err() || outcome.as_ref().is_ok_and(|(fd, _)| fd.is_err()),
                "mode {mode}: false success"
            );
            assert_eq!(transfers, i32::from(mode == 6));
            assert_eq!(live(), mode != 6, "mode {mode}: wrong descriptor owner");
            if mode == 4 {
                env.set_field(service.as_obj(), "failUnregister", "Z", JValue::Bool(1))
                    .unwrap();
                assert!(
                    jni_call::handled(env, "failed undelivered release", || {
                        env.call_method(
                            service.as_obj(),
                            "finishLocalFrontend",
                            "(J)V",
                            &[JValue::Long(12)],
                        )
                    })
                    .is_err()
                );
                assert!(!env.exception_check().unwrap());
                assert!(!live(), "unregister failure stranded an undelivered fd");
                assert!(
                    env.get_field(service.as_obj(), "owned", "Z")
                        .unwrap()
                        .z()
                        .unwrap()
                );
                env.set_field(service.as_obj(), "failUnregister", "Z", JValue::Bool(0))
                    .unwrap();
            }
            jni_call::handled(env, "finish undelivered", || {
                env.call_method(
                    service.as_obj(),
                    "finishLocalFrontend",
                    "(J)V",
                    &[JValue::Long(12)],
                )
            })
            .unwrap();
            assert!(!live(), "mode {mode}: leaked descriptor after finish");
        }
        assert!(!env.exception_check().unwrap());
    }
    for name in [
        "EstablishError",
        "OtherLegacyAlwaysOnVpn",
        "OtherAlwaysOnApp",
        "NotPrepared",
    ] {
        let class = format!("net/mullvad/talpid/model/CreateTunResult${name}");
        let result = env.auto_local(env.new_object(class, "()V", &[]).unwrap());
        let decoded = descriptor::decode(env, result.as_obj()).unwrap();
        assert!(matches!(
            (&decoded, name),
            (descriptor::OpenResult::EstablishError, "EstablishError")
                | (
                    descriptor::OpenResult::OtherLegacyAlwaysOnVpn,
                    "OtherLegacyAlwaysOnVpn"
                )
                | (
                    descriptor::OpenResult::OtherAlwaysOnApp(_),
                    "OtherAlwaysOnApp"
                )
                | (descriptor::OpenResult::NotPrepared, "NotPrepared")
        ));
        if let descriptor::OpenResult::OtherAlwaysOnApp(app) = decoded {
            assert_eq!(app, "other.vpn");
        }
    }
}
