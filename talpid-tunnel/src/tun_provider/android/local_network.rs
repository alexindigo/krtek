//! JNI names and socket preparation codes shared with TalpidVpnService.
use super::{Error, VpnServiceConfig};
use jnix::{
    IntoJava, JnixEnv,
    jni::objects::{AutoLocal, JObject, JValue},
};
use std::os::fd::{OwnedFd, RawFd};
use talpid_types::android::AndroidContext;
mod descriptor;
mod jni_call;
use jni_call::handled;

pub const METHODS: [(&str, &str); 9] = [
    (
        "openLocalFrontend",
        "(J[Ljava/lang/String;[Ljava/lang/String;)Lnet/mullvad/talpid/model/CreateTunResult;",
    ),
    ("finishLocalFrontend", "(J)V"),
    ("isLocalFrontendActive", "()Z"),
    ("prepareLocalSocket", "(IJJZ)I"),
    (
        "openSecuredFrontend",
        "(JLnet/mullvad/talpid/model/TunConfig;)Lnet/mullvad/talpid/model/CreateTunResult;",
    ),
    ("bindLocalFrontend", "(JLjava/lang/String;)Z"),
    (
        "handoverLocalFrontend",
        "(JJ[Ljava/lang/String;[Ljava/lang/String;)Lnet/mullvad/talpid/model/CaptureHandoverResult;",
    ),
    (
        "handoverSecuredFrontend",
        "(JJLnet/mullvad/talpid/model/TunConfig;)Lnet/mullvad/talpid/model/CaptureHandoverResult;",
    ),
    descriptor::TAKE,
];

fn string_array<'a, 'b>(
    env: &'b jnix::jni::JNIEnv<'a>,
    name: &'static str,
    values: &[String],
) -> Result<AutoLocal<'a, 'b>, Error> {
    let size = i32::try_from(values.len()).map_err(|_| Error::TunnelDeviceError)?;
    let array = env
        .new_object_array(size, "java/lang/String", JObject::null())
        .map_err(|e| Error::CallMethod(name, e))?;
    let array = env.auto_local(JObject::from(array));
    // Guard the array before any fallible element conversion on this attached thread.
    for (index, value) in values.iter().enumerate() {
        let string = env
            .new_string(value)
            .map_err(|e| Error::CallMethod(name, e))?;
        let string = env.auto_local(JObject::from(string));
        env.set_object_array_element(array.as_obj().into_inner(), index as i32, string.as_obj())
            .map_err(|e| Error::CallMethod(name, e))?;
    }
    Ok(array)
}

fn decode_error(error: descriptor::DecodeError) -> Error {
    match error {
        descriptor::DecodeError::Jni(error) => Error::CallMethod("capture result", error),
        descriptor::DecodeError::InvalidResult => Error::TunnelDeviceError,
    }
}

fn decode_descriptor(env: &jnix::jni::JNIEnv<'_>, result: JObject<'_>) -> Result<RawFd, Error> {
    use descriptor::OpenResult;
    match descriptor::decode(env, result).map_err(decode_error)? {
        OpenResult::Descriptor(fd) => Ok(fd),
        OpenResult::EstablishError => Err(Error::TunnelDeviceError),
        OpenResult::OtherLegacyAlwaysOnVpn => Err(Error::OtherLegacyAlwaysOnVpn),
        OpenResult::OtherAlwaysOnApp(app_name) => Err(Error::OtherAlwaysOnApp { app_name }),
        OpenResult::NotPrepared => Err(Error::NotPrepared),
    }
}

pub enum FrontendHandoverConfig<'a> {
    Partial(&'a super::super::PartialConfig),
    Secured(crate::tun_provider::TunConfig),
}

pub struct FrontendHandoverResult {
    pub descriptor: Result<OwnedFd, Error>,
    pub predecessor_retained: bool,
}

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

    pub fn capture_network(
        &self,
    ) -> std::sync::Arc<talpid_types::capture_network::CaptureNetworkFeed> {
        self.context.capture_network.clone()
    }

    pub fn capture_api_level(&self) -> Result<i32, Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        handled(&env, "Build.VERSION.SDK_INT", || {
            env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
                .and_then(|value| value.i())
                .map_err(|e| Error::CallMethod("Build.VERSION.SDK_INT", e))
        })
    }

    pub fn open_frontend(
        &self,
        generation: i64,
        config: &super::super::PartialConfig,
    ) -> Result<OwnedFd, Error> {
        let env = JnixEnv::from(
            self.context
                .jvm
                .attach_current_thread_as_daemon()
                .map_err(Error::AttachJvmToThread)?,
        );
        let (name, signature) = METHODS[0];
        handled(&env, name, || {
            let routes = string_array(&env, name, &config.routes)?;
            let excluded = string_array(&env, name, &config.excluded_packages)?;
            let result = env
                .call_method(
                    self.context.vpn_service.as_obj(),
                    name,
                    signature,
                    &[
                        JValue::Long(generation),
                        JValue::Object(routes.as_obj()),
                        JValue::Object(excluded.as_obj()),
                    ],
                )
                .and_then(|value| value.l())
                .map_err(|e| Error::CallMethod(name, e))?;
            let result = env.auto_local(result);
            let raw = decode_descriptor(&env, result.as_obj())?;
            descriptor::take(&env, self.context.vpn_service.as_obj(), generation, raw)
                .map_err(decode_error)
        })
    }

    pub fn open_secured_frontend(
        &self,
        generation: i64,
        config: crate::tun_provider::TunConfig,
    ) -> Result<OwnedFd, Error> {
        let env = JnixEnv::from(
            self.context
                .jvm
                .attach_current_thread_as_daemon()
                .map_err(Error::AttachJvmToThread)?,
        );
        let (name, signature) = METHODS[4];
        handled(&env, name, || {
            let config = VpnServiceConfig::new(config).into_java(&env);
            let result = env
                .call_method(
                    self.context.vpn_service.as_obj(),
                    name,
                    signature,
                    &[JValue::Long(generation), JValue::Object(config.as_obj())],
                )
                .and_then(|v| v.l())
                .map_err(|e| Error::CallMethod(name, e))?;
            let result = env.auto_local(result);
            let raw = decode_descriptor(&env, result.as_obj())?;
            descriptor::take(&env, self.context.vpn_service.as_obj(), generation, raw)
                .map_err(decode_error)
        })
    }

    pub fn bind_frontend(&self, generation: i64, interface: &str) -> Result<bool, Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        let (name, signature) = METHODS[5];
        handled(&env, name, || {
            let interface = env
                .new_string(interface)
                .map_err(|e| Error::CallMethod(name, e))?;
            let interface = env.auto_local(JObject::from(interface));
            env.call_method(
                self.context.vpn_service.as_obj(),
                name,
                signature,
                &[JValue::Long(generation), JValue::Object(interface.as_obj())],
            )
            .and_then(|v| v.z())
            .map_err(|e| Error::CallMethod(name, e))
        })
    }

    pub fn handover_frontend(
        &self,
        predecessor: i64,
        generation: i64,
        config: FrontendHandoverConfig<'_>,
    ) -> FrontendHandoverResult {
        let call = || -> Result<(Result<OwnedFd, Error>, bool), Error> {
            let env = JnixEnv::from(
                self.context
                    .jvm
                    .attach_current_thread_as_daemon()
                    .map_err(Error::AttachJvmToThread)?,
            );
            let (name, signature) = METHODS[match &config {
                FrontendHandoverConfig::Partial(_) => 6,
                FrontendHandoverConfig::Secured(_) => 7,
            }];
            handled(&env, name, || {
                let (argument, excluded) = match config {
                    FrontendHandoverConfig::Partial(config) => (
                        string_array(&env, name, &config.routes)?,
                        Some(string_array(&env, name, &config.excluded_packages)?),
                    ),
                    FrontendHandoverConfig::Secured(config) => {
                        (VpnServiceConfig::new(config).into_java(&env), None)
                    }
                };
                let mut arguments = vec![
                    JValue::Long(predecessor),
                    JValue::Long(generation),
                    JValue::Object(argument.as_obj()),
                ];
                if let Some(excluded) = &excluded {
                    arguments.push(JValue::Object(excluded.as_obj()));
                }
                let result = env
                    .call_method(
                        self.context.vpn_service.as_obj(),
                        name,
                        signature,
                        &arguments,
                    )
                    .and_then(|v| v.l())
                    .map_err(|e| Error::CallMethod(name, e))?;
                let result = env.auto_local(result);
                descriptor::handover(
                    &env,
                    self.context.vpn_service.as_obj(),
                    generation,
                    result.as_obj(),
                    |result| decode_descriptor(&env, result),
                    decode_error,
                )
            })
        };
        match call() {
            Ok((descriptor, predecessor_retained)) => FrontendHandoverResult {
                descriptor,
                predecessor_retained,
            },
            Err(error) => FrontendHandoverResult {
                descriptor: Err(error),
                predecessor_retained: false,
            },
        }
    }

    pub fn finish_frontend(&self, generation: i64) -> Result<(), Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        let (name, signature) = METHODS[1];
        handled(&env, name, || {
            env.call_method(
                self.context.vpn_service.as_obj(),
                name,
                signature,
                &[JValue::Long(generation)],
            )
            .map_err(|e| Error::CallMethod(name, e))?;
            Ok(())
        })
    }

    pub fn frontend_active(&self) -> Result<bool, Error> {
        let env = self
            .context
            .jvm
            .attach_current_thread_as_daemon()
            .map_err(Error::AttachJvmToThread)?;
        let (name, signature) = METHODS[2];
        handled(&env, name, || {
            env.call_method(self.context.vpn_service.as_obj(), name, signature, &[])
                .and_then(|v| v.z())
                .map_err(|e| Error::CallMethod(name, e))
        })
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
        handled(&env, name, || {
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
        })
    }
}
