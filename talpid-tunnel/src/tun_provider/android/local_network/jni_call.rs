//! Handled JNI work on attached native workers must not retain Java exceptions.
use jnix::jni::{
    JNIEnv,
    objects::{JObject, JString},
};

struct HandledCall<'borrow, 'env> {
    env: &'borrow JNIEnv<'env>,
    name: &'static str,
}

impl Drop for HandledCall<'_, '_> {
    fn drop(&mut self) {
        if !self.env.exception_check().unwrap_or(true) {
            return;
        }
        // ExceptionOccurred and ExceptionClear are allowed with a pending
        // exception. Clear BEFORE calling any method on the retained throwable.
        let throwable = self.env.exception_occurred();
        let _ = self.env.exception_clear();
        let diagnostic = throwable.ok().and_then(|throwable| {
            let throwable = self.env.auto_local(JObject::from(throwable));
            if throwable.as_obj().is_null() {
                return None;
            }
            let description = self
                .env
                .call_method(throwable.as_obj(), "toString", "()Ljava/lang/String;", &[])
                .and_then(|value| value.l())
                .ok()?;
            let description = self.env.auto_local(description);
            self.env
                .get_string(JString::from(description.as_obj()))
                .ok()
                .map(|value| String::from(value).chars().take(1024).collect::<String>())
        });
        // A broken Throwable.toString must not leave a replacement exception.
        let _ = self.env.exception_clear();
        log::warn!(
            "Frontend JNI {} Java exception: {}",
            self.name,
            diagnostic.as_deref().unwrap_or("diagnostic unavailable")
        );
    }
}

/// Preserve the actual failure, while bounding diagnostics and clearing the
/// thread-local throwable on every exit, including conversion unwinding.
pub(super) fn handled<T, E: std::fmt::Debug>(
    env: &JNIEnv<'_>,
    name: &'static str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let _call = HandledCall { env, name };
    let result = operation();
    if let Err(error) = &result {
        log::warn!("Frontend JNI {name} failed: {error:?}");
    }
    result
}
