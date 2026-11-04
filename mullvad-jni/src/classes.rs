/// Optional feature classes are preloaded inside its non-fatal registration boundary.
pub const LOCAL_NETWORK_CLASSES: &[&str] = &[
    "net/mullvad/talpid/model/LocalNetworkSnapshot",
    "net/mullvad/talpid/model/LocalPhysicalNetwork",
    "net/mullvad/talpid/model/LocalPhysicalAddress",
    "net/mullvad/talpid/model/LocalPhysicalRoute",
];

pub const CAPTURE_NETWORK_CLASSES: &[&str] = &[
    "java/lang/Integer",
    "net/mullvad/talpid/model/CaptureNetworkObservation",
    "net/mullvad/talpid/model/CaptureRoute",
];

pub const CLASSES: &[&str] = &[
    "java/lang/Boolean",
    "java/net/InetAddress",
    "java/net/InetSocketAddress",
    "java/util/ArrayList",
    "java/util/HashMap",
    "net/mullvad/mullvadvpn/app/service/MullvadDaemon",
    "net/mullvad/mullvadvpn/app/service/MullvadVpnService",
    "net/mullvad/talpid/model/InetNetwork",
    "net/mullvad/talpid/model/TunConfig",
    "net/mullvad/talpid/model/NetworkState",
    "net/mullvad/talpid/model/RouteInfo",
    "net/mullvad/talpid/model/CreateTunResult$Success",
    "net/mullvad/talpid/model/CreateTunResult$InvalidDnsServers",
    "net/mullvad/talpid/model/CreateTunResult$InvalidIpv6Config",
    "net/mullvad/talpid/model/CreateTunResult$OtherLegacyAlwaysOnVpn",
    "net/mullvad/talpid/model/CreateTunResult$OtherAlwaysOnApp",
    "net/mullvad/talpid/model/CreateTunResult$NotPrepared",
    "net/mullvad/talpid/model/CreateTunResult$EstablishError",
    "net/mullvad/talpid/ConnectivityListener",
    "net/mullvad/talpid/TalpidVpnService",
    "net/mullvad/mullvadvpn/lib/endpoint/ApiEndpointOverride",
    "net/mullvad/talpid/model/Connectivity$Online",
    "net/mullvad/talpid/model/Connectivity$Offline",
    "net/mullvad/talpid/model/Connectivity$PresumeOnline",
    "net/mullvad/talpid/model/IpAvailability",
];
