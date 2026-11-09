//! Result conversion never owns a raw fd. The service retains its descriptor
//! until the last primitive transfer, so getter/acknowledgement failures cannot
//! strand a detached descriptor or require adopting one twice.
use jnix::jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub(super) const TAKE: (&str, &str) = ("takeLocalFrontendDescriptor", "(J)I");

#[derive(Debug)]
pub(super) enum DecodeError {
    Jni(jnix::jni::errors::Error),
    InvalidResult,
}

impl From<jnix::jni::errors::Error> for DecodeError {
    fn from(error: jnix::jni::errors::Error) -> Self {
        Self::Jni(error)
    }
}

#[derive(Debug)]
pub(super) enum OpenResult {
    Descriptor(RawFd),
    EstablishError,
    OtherLegacyAlwaysOnVpn,
    OtherAlwaysOnApp(String),
    NotPrepared,
}

// Unlike FromJava's derived getters, every conversion here is fallible. No
// detached fd is exposed until all discriminants and metadata have been read.
pub(super) fn decode(env: &JNIEnv<'_>, result: JObject<'_>) -> Result<OpenResult, DecodeError> {
    if result.is_null() {
        return Err(DecodeError::InvalidResult);
    }
    let class = env.auto_local(JObject::from(env.get_object_class(result)?));
    let name = env
        .call_method(class.as_obj(), "getName", "()Ljava/lang/String;", &[])?
        .l()?;
    let name = env.auto_local(name);
    let name = String::from(env.get_string(JString::from(name.as_obj()))?);
    Ok(
        match name.strip_prefix("net.mullvad.talpid.model.CreateTunResult$") {
            Some("Success") => {
                let fd = env.call_method(result, "getTunFd", "()I", &[])?.i()?;
                if fd < 0 {
                    return Err(DecodeError::InvalidResult);
                }
                OpenResult::Descriptor(fd)
            }
            Some("EstablishError") => OpenResult::EstablishError,
            Some("OtherLegacyAlwaysOnVpn") => OpenResult::OtherLegacyAlwaysOnVpn,
            Some("OtherAlwaysOnApp") => {
                let name = env
                    .call_method(result, "getAppName", "()Ljava/lang/String;", &[])?
                    .l()?;
                let name = env.auto_local(name);
                OpenResult::OtherAlwaysOnApp(String::from(
                    env.get_string(JString::from(name.as_obj()))?,
                ))
            }
            Some("NotPrepared") => OpenResult::NotPrepared,
            _ => return Err(DecodeError::InvalidResult),
        },
    )
}

pub(super) fn take(
    env: &JNIEnv<'_>,
    service: JObject<'_>,
    generation: i64,
    expected: RawFd,
) -> Result<OwnedFd, DecodeError> {
    let raw = env
        .call_method(service, TAKE.0, TAKE.1, &[JValue::Long(generation)])?
        .i()?;
    if raw < 0 {
        return Err(DecodeError::InvalidResult);
    }
    // SAFETY: takeLocalFrontendDescriptor detached and removed the sole epoch
    // descriptor. Adopt immediately, before any validation or other JNI work.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if raw != expected {
        return Err(DecodeError::InvalidResult);
    }
    Ok(fd)
}

pub(super) fn handover<'env, E>(
    env: &JNIEnv<'env>,
    service: JObject<'env>,
    generation: i64,
    result: JObject<'env>,
    decode: impl FnOnce(JObject<'env>) -> Result<RawFd, E>,
    error: impl Fn(DecodeError) -> E,
) -> Result<(Result<OwnedFd, E>, bool), E> {
    let value = env
        .call_method(
            result,
            "getResult",
            "()Lnet/mullvad/talpid/model/CreateTunResult;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(|e| error(e.into()))?;
    let value = env.auto_local(value);
    let retained = env
        .call_method(result, "getPredecessorRetained", "()Z", &[])
        .and_then(|value| value.z())
        .map_err(|e| error(e.into()))?;
    let fd = decode(value.as_obj())
        .and_then(|expected| take(env, service, generation, expected).map_err(error));
    Ok((fd, retained))
}
