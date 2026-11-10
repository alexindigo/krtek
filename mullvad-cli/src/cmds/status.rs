use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use futures::StreamExt;
use mullvad_management_interface::{MullvadProxyClient, client::DaemonEvent};
use mullvad_types::settings::local_network_access::status::LocalNetworkStatus;
use mullvad_types::{device::DeviceState, states::TunnelState};
use serde::Serialize;
use std::fmt::Debug;

use crate::format;

#[derive(Subcommand, Debug, PartialEq)]
pub enum Status {
    /// Listen for tunnel state changes
    Listen,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Enable verbose output
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Enable debug output
    #[arg(long, short = 'd', conflicts_with_all = ["verbose", "json"])]
    debug: bool,

    /// Format output as JSON
    #[arg(long, short = 'j', conflicts_with_all = ["verbose", "debug"])]
    json: bool,
}

impl Status {
    pub async fn listen(
        mut rpc: MullvadProxyClient,
        args: StatusArgs,
        mut previous_tunnel_state: TunnelState,
    ) -> Result<()> {
        let mut event_stream = rpc.events_listen().await?;
        while let Some(event) = event_stream.next().await {
            match event? {
                DaemonEvent::TunnelState(new_state) => {
                    if !print_debug_or_json(&args, "New tunnel state", &new_state)? {
                        format::print_state(&new_state, Some(&previous_tunnel_state), args.verbose);
                        previous_tunnel_state = new_state;
                    }
                }
                DaemonEvent::Settings(settings) => {
                    print_debug_or_json(&args, "New settings", &settings)?;
                }
                DaemonEvent::RelayList(relay_list) => {
                    print_debug_or_json(&args, "New relay list", &relay_list)?;
                }
                DaemonEvent::AppVersionInfo(app_version_info) => {
                    print_debug_or_json(&args, "New app version info", &app_version_info)?;
                }
                DaemonEvent::Device(device) => {
                    print_debug_or_json(&args, "Device event", &device)?;
                }
                DaemonEvent::RemoveDevice(device) => {
                    print_debug_or_json(&args, "Remove device event", &device)?;
                }
                DaemonEvent::NewAccessMethod(access_method) => {
                    print_debug_or_json(&args, "New access method", &access_method)?;
                }
                DaemonEvent::LocalNetworkStatus(status) => {
                    if local_network_summary_visible(&args, &status) {
                        print_local_network_summary(&status);
                    }
                }
                DaemonEvent::LeakDetected(leak) => {
                    #[derive(Debug, Serialize)]
                    struct Leak {
                        interface: String,
                        reachable: Vec<std::net::IpAddr>,
                    }
                    let leak = Leak {
                        interface: leak.interface,
                        reachable: leak.reachable_nodes,
                    };
                    print_debug_or_json(&args, "Leak detected", &leak)?;
                }
            }
        }
        Ok(())
    }
}

pub async fn handle(cmd: Option<Status>, args: StatusArgs) -> Result<()> {
    let mut rpc = MullvadProxyClient::new().await?;
    let state = rpc.get_tunnel_state().await?;
    let device = rpc.get_device().await?;

    print_account_logged_out(&state, &device);

    if !print_debug_or_json(&args, "New tunnel state", &state)? {
        format::print_state(&state, None, args.verbose);
    }

    if let Some(status) = local_network_snapshot(&args, rpc.get_local_network_status()).await {
        print_local_network_summary(&status);
    }

    if cmd == Some(Status::Listen) {
        Status::listen(rpc, args, state).await?;
    }
    Ok(())
}

fn print_account_logged_out(state: &TunnelState, device: &DeviceState) {
    match state {
        TunnelState::Connecting { .. } | TunnelState::Connected { .. } | TunnelState::Error(_) => {
            match device {
                DeviceState::LoggedOut => {
                    println!("Warning: You are not logged in to an account.")
                }
                DeviceState::Revoked => println!("Warning: This device has been revoked."),
                DeviceState::LoggedIn(_) => (),
            }
        }
        TunnelState::Disconnected { .. } | TunnelState::Disconnecting(_) => (),
    }
}

fn local_network_summary_visible(args: &StatusArgs, status: &LocalNetworkStatus) -> bool {
    !args.json && !args.debug && (status.observer_available || !status.rules.is_empty())
}

async fn local_network_snapshot(
    args: &StatusArgs,
    fetch: impl Future<Output = mullvad_management_interface::client::Result<LocalNetworkStatus>>,
) -> Option<LocalNetworkStatus> {
    if args.json || args.debug {
        return None;
    }
    match fetch.await {
        Ok(status) => local_network_summary_visible(args, &status).then_some(status),
        Err(error) => {
            eprintln!("Warning: Failed to fetch local network status: {error}");
            None
        }
    }
}

fn print_local_network_summary(status: &LocalNetworkStatus) {
    use mullvad_types::settings::local_network_access::status::{
        ForwardingAvailability, RuleState,
    };
    let forwarding = match status.forwarding {
        ForwardingAvailability::NotAvailable => "forwarding not available",
        ForwardingAvailability::Off => "delivery off",
        ForwardingAvailability::Active => "local rules ready",
        ForwardingAvailability::PausedWhileConnected => {
            "delivery paused while connecting or connected"
        }
        ForwardingAvailability::Failed => "delivery failed",
    };
    let ready = status
        .rules
        .iter()
        .filter(|rule| matches!(rule.state, RuleState::ConditionsMet | RuleState::Forwarding))
        .count();
    println!(
        "Local network: {forwarding}; {ready}/{} rule conditions met; observer {}",
        status.rules.len(),
        if status.observer_available {
            "available"
        } else {
            "unavailable"
        }
    );
}

/// Print the given value as debug or JSON output based on the provided arguments.
///
/// Returns `true` if the value was printed. Returns `false` otherwise, i.e. if
/// both `args.debug` and `args.json` are `false`.
fn print_debug_or_json<T: Debug + Serialize>(
    args: &StatusArgs,
    debug_message: &str,
    t: &T,
) -> Result<bool> {
    if args.debug {
        println!("{debug_message}: {t:#?}");
        Ok(true)
    } else if args.json {
        let json = serde_json::to_string(&t).context("Failed to format output as JSON")?;
        println!("{json}");
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mullvad_types::settings::local_network_access::LocalNetworkAccess;

    #[test]
    fn snapshot_and_events_share_text_mode_and_availability_visibility() {
        for json in [false, true] {
            for debug in [false, true] {
                for observer in [false, true] {
                    for rules in [false, true] {
                        let args = StatusArgs {
                            verbose: false,
                            debug,
                            json,
                        };
                        let mut status = LocalNetworkStatus::from_observation(
                            &LocalNetworkAccess::default(),
                            None,
                        );
                        status.observer_available = observer;
                        if rules {
                            use mullvad_types::settings::local_network_access::status::{
                                LocalRuleStatus, RuleState,
                            };
                            status.rules.push(LocalRuleStatus {
                                id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
                                state: RuleState::ConditionsMet,
                            });
                        }
                        assert_eq!(
                            local_network_summary_visible(&args, &status),
                            !json && !debug && (observer || rules)
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn auxiliary_status_failure_is_nonfatal() {
        let args = StatusArgs {
            verbose: false,
            debug: false,
            json: false,
        };
        let result = local_network_snapshot(&args, async {
            Err(mullvad_management_interface::Error::MissingDaemonEvent)
        })
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn structured_modes_do_not_poll_the_auxiliary_rpc() {
        for (json, debug) in [(true, false), (false, true)] {
            let args = StatusArgs {
                verbose: false,
                debug,
                json,
            };
            assert!(
                local_network_snapshot(&args, async {
                    panic!("structured output must not fetch a text-only summary")
                })
                .await
                .is_none()
            );
        }
    }
}
