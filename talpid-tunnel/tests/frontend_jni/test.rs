//! Run by the task-owned builder JVM harness using this exact production module.
#[path = "../../src/tun_provider/android/local_network/jni_call.rs"]
mod jni_call;
use jnix::jni::{
    InitArgsBuilder, JNIVersion, JavaVM,
    objects::{JObject, JValue},
};
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
            env.call_method(service, "finishLocalFrontend", "()V", &[])
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
