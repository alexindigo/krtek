//! JNI names and socket preparation codes shared with TalpidVpnService.
use super::{CreateTunResult, Error};
use jnix::{
    FromJava, JnixEnv,
    jni::objects::{JObject, JValue},
};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use talpid_types::android::AndroidContext;

pub const METHODS: [(&str, &str); 4] = [
    (
        "openLocalFrontend",
        "([Ljava/lang/String;)Lnet/mullvad/talpid/model/CreateTunResult;",
    ),
    ("finishLocalFrontend", "()V"),
    ("isLocalFrontendActive", "()Z"),
    ("prepareLocalSocket", "(IJJZ)I"),
];

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("Local observation changed")]
    Stale,
    #[error("Socket protection failed")]
    ProtectFailed,
    #[error("Socket binding failed")]
    BindFailed,
    #[error("Local frontend is inactive")]
    Inactive,
    #[error("Invalid socket preparation result")]
    InvalidResult,
    #[error("Local socket JNI call failed")]
    Platform(#[source] Error),
}

#[derive(Clone)]
pub struct LocalNetworkPlatform {
    context: AndroidContext,
}

impl LocalNetworkPlatform {
    pub fn new(context: AndroidContext) -> Self {
        Self { context }
    }

    pub fn open_frontend(&self, routes: &[String]) -> Result<OwnedFd, Error> {
        let env = JnixEnv::from(
            self.context
                .jvm
                .attach_current_thread_as_daemon()
                .map_err(Error::AttachJvmToThread)?,
        );
        let (name, signature) = METHODS[0];
        let size = i32::try_from(routes.len()).map_err(|_| Error::TunnelDeviceError)?;
        let array = env
            .new_object_array(size, "java/lang/String", JObject::null())
            .map_err(|e| Error::CallMethod(name, e))?;
        let array_ref = env.auto_local(JObject::from(array));
        for (index, route) in routes.iter().enumerate() {
            let string = env
                .new_string(route)
                .map_err(|e| Error::CallMethod(name, e))?;
            env.set_object_array_element(array, index as i32, string)
                .map_err(|e| Error::CallMethod(name, e))?;
            env.delete_local_ref(*string)
                .map_err(|e| Error::CallMethod(name, e))?;
        }
        let result = env
            .call_method(
                self.context.vpn_service.as_obj(),
                name,
                signature,
                &[JValue::Object(array_ref.as_obj())],
            )
            .and_then(|value| value.l())
            .map_err(|e| Error::CallMethod(name, e))?;
        let result = env.auto_local(result);
        let raw = Result::<RawFd, Error>::from(CreateTunResult::from_java(&env, result.as_obj()))?;
        if raw < 0 {
            return Err(Error::TunnelDeviceError);
        }
        // SAFETY: Kotlin detached the sole descriptor and retains no cached/adopted copy.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    pub fn finish_frontend(&self) -> Result<(), Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        let (name, signature) = METHODS[1];
        env.call_method(self.context.vpn_service.as_obj(), name, signature, &[])
            .map_err(|e| Error::CallMethod(name, e))?;
        Ok(())
    }

    pub fn frontend_active(&self) -> Result<bool, Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        let (name, signature) = METHODS[2];
        env.call_method(self.context.vpn_service.as_obj(), name, signature, &[])
            .and_then(|v| v.z())
            .map_err(|e| Error::CallMethod(name, e))
    }

    pub fn prepare(
        &self,
        fd: RawFd,
        network_handle: i64,
        sequence: i64,
        needs_wifi_name: bool,
    ) -> Result<(), PrepareError> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(|e| PrepareError::Platform(Error::AttachJvmToThread(e)))?;
        let (name, signature) = METHODS[3];
        let code = env
            .call_method(
                self.context.vpn_service.as_obj(),
                name,
                signature,
                &[
                    JValue::Int(fd),
                    JValue::Long(network_handle),
                    JValue::Long(sequence),
                    JValue::Bool(needs_wifi_name.into()),
                ],
            )
            .and_then(|v| v.i())
            .map_err(|e| PrepareError::Platform(Error::CallMethod(name, e)))?;
        match code {
            0 => Ok(()),
            1 => Err(PrepareError::Stale),
            2 => Err(PrepareError::ProtectFailed),
            3 => Err(PrepareError::BindFailed),
            4 => Err(PrepareError::Inactive),
            _ => Err(PrepareError::InvalidResult),
        }
    }
}
