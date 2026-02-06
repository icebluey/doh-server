use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8};
use std::sync::Arc;
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::time::Duration;

use clap::{Arg, ArgAction::Append, ArgAction::SetTrue};
use libdoh::*;
use url::{Host, Url};

use crate::constants::*;

fn exit_with_error(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    std::process::exit(1);
}

pub fn parse_opts(globals: &mut Globals) {
    use crate::utils::{verify_sock_addr, verify_upstream};

    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let max_concurrent_streams = MAX_CONCURRENT_STREAMS.to_string();
    let min_ttl = MIN_TTL.to_string();
    let max_ttl = MAX_TTL.to_string();
    let err_ttl = ERR_TTL.to_string();

    let _ = include_str!("../Cargo.toml");
    let options = command!()
        .arg(
            Arg::new("hostname")
                .short('H')
                .long("hostname")
                .num_args(1)
                .help("Host name (not IP address) DoH clients will use to connect"),
        )
        .arg(
            Arg::new("public_address")
                .short('g')
                .long("public-address")
                .num_args(1..)
                .action(clap::ArgAction::Append)
                .help("External IP address(es) DoH clients will connect to (can be specified multiple times)"),
        )
        .arg(
            Arg::new("public_port")
                .short('j')
                .long("public-port")
                .num_args(1)
                .help("External port DoH clients will connect to, if not 443"),
        )
        .arg(
            Arg::new("listen_address")
                .short('l')
                .long("listen-address")
                .num_args(1)
                .action(Append)
                .value_parser(verify_sock_addr)
                .help("Address to listen to"),
        )
        .arg(
            Arg::new("upstream")
                .short('u')
                .long("upstream")
                .num_args(1)
                .default_value(SERVER_ADDRESS)
                .value_parser(verify_upstream)
                .help("Address or DoH/DoT URL to connect to (https://, h3://, tls://)"),
        )
        .arg(
            Arg::new("local_bind_address")
                .short('b')
                .long("local-bind-address")
                .num_args(1)
                .value_parser(verify_sock_addr)
                .help("Address to connect from"),
        )
        .arg(
            Arg::new("bootstrap")
                .short('B')
                .long("bootstrap")
                .num_args(1)
                .action(Append)
                .value_name("ip:port")
                .value_parser(verify_sock_addr)
                .help(
                    "Bootstrap DNS for DoH and DoT, can be specified multiple times (default: use system-provided)",
                ),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .num_args(1)
                .default_value(PATH)
                .help("URI path"),
        )
        .arg(
            Arg::new("max_clients")
                .short('c')
                .long("max-clients")
                .num_args(1)
                .default_value(max_clients)
                .help("Maximum number of simultaneous clients"),
        )
        .arg(
            Arg::new("max_concurrent")
                .short('C')
                .long("max-concurrent")
                .num_args(1)
                .default_value(max_concurrent_streams)
                .help("Maximum number of concurrent requests per client"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .num_args(1)
                .default_value(timeout_sec)
                .help("Timeout, in seconds"),
        )
        .arg(
            Arg::new("min_ttl")
                .short('T')
                .long("min-ttl")
                .num_args(1)
                .default_value(min_ttl)
                .help("Minimum TTL, in seconds"),
        )
        .arg(
            Arg::new("max_ttl")
                .short('X')
                .long("max-ttl")
                .num_args(1)
                .default_value(max_ttl)
                .help("Maximum TTL, in seconds"),
        )
        .arg(
            Arg::new("err_ttl")
                .short('E')
                .long("err-ttl")
                .num_args(1)
                .default_value(err_ttl)
                .help("TTL for errors, in seconds"),
        )
        .arg(
            Arg::new("disable_keepalive")
                .short('K')
                .action(SetTrue)
                .long("disable-keepalive")
                .help("Disable keepalive"),
        )
        .arg(
            Arg::new("disable_post")
                .short('P')
                .action(SetTrue)
                .long("disable-post")
                .help("Disable POST queries"),
        )
        .arg(
            Arg::new("allow_odoh_post")
                .short('O')
                .action(SetTrue)
                .long("allow-odoh-post")
                .help("Allow POST queries over ODoH even if they have been disabed for DoH"),
        )
        .arg(
            Arg::new("enable_ecs")
                .long("enable-ecs")
                .action(SetTrue)
                .help("Enable EDNS Client Subnet (forward client IP to upstream DNS)"),
        )
        .arg(
            Arg::new("ecs_prefix_v4")
                .long("ecs-prefix-v4")
                .num_args(1)
                .default_value("24")
                .help("EDNS Client Subnet prefix length for IPv4 addresses"),
        )
        .arg(
            Arg::new("ecs_prefix_v6")
                .long("ecs-prefix-v6")
                .num_args(1)
                .default_value("56")
                .help("EDNS Client Subnet prefix length for IPv6 addresses"),
        );

    #[cfg(feature = "tls")]
    let options = options
        .arg(
            Arg::new("tls_cert_path")
                .short('i')
                .long("tls-cert-path")
                .num_args(1)
                .help(
                    "Path to the PEM/PKCS#8-encoded certificates (only required for built-in TLS)",
                ),
        )
        .arg(
            Arg::new("tls_cert_key_path")
                .short('I')
                .long("tls-cert-key-path")
                .num_args(1)
                .help("Path to the PEM-encoded secret keys (only required for built-in TLS)"),
        );

    let matches = options.get_matches();

    // Parse listen addresses
    globals.listen_addresses = match matches.get_many::<String>("listen_address") {
        Some(values) => values
            .map(|value| {
                value.parse().unwrap_or_else(|e| {
                    exit_with_error(&format!("Invalid listen address '{}': {}", value, e))
                })
            })
            .collect(),
        None => vec![LISTEN_ADDRESS.parse().unwrap_or_else(|e| {
            exit_with_error(&format!(
                "Invalid default listen address '{}': {}",
                LISTEN_ADDRESS, e
            ))
        })],
    };

    // Parse upstream
    let server_address_str = matches
        .get_one::<String>("upstream")
        .expect("upstream has a default value");
    globals.upstream = if server_address_str.starts_with("http://")
        || server_address_str.starts_with("https://")
        || server_address_str.starts_with("h3://")
        || server_address_str.starts_with("tls://")
    {
        let url = Url::parse(server_address_str).unwrap_or_else(|e| {
            exit_with_error(&format!("Invalid URL '{}': {}", server_address_str, e))
        });
        match url.scheme() {
            "https" | "h3" => {
                let host = url.host_str().unwrap_or_else(|| {
                    exit_with_error(&format!(
                        "DoH URL '{}' must include a host",
                        server_address_str
                    ))
                }).to_string();
                let host_header = match url.host() {
                    Some(Host::Ipv6(ip)) => format!("[{}]", ip),
                    Some(Host::Ipv4(ip)) => ip.to_string(),
                    Some(Host::Domain(domain)) => domain.to_string(),
                    None => {
                        exit_with_error(&format!(
                            "DoH URL '{}' must include a host",
                            server_address_str
                        ))
                    }
                };
                let port = if url.scheme() == "https" {
                    url.port_or_known_default().unwrap_or(443)
                } else {
                    url.port().unwrap_or(443)
                };
                let mut path = url.path().to_string();
                if path.is_empty() || path == "/" {
                    path = PATH.to_string();
                }
                if let Some(query) = url.query() {
                    path = format!("{path}?{query}");
                }
                let authority = if url.port().is_some() {
                    format!("{host_header}:{port}")
                } else {
                    host_header
                };
                let h3_only = url.scheme() == "h3";
                Upstream::Doh(DohUpstream {
                    url,
                    host,
                    port,
                    path,
                    authority,
                    h3_only,
                    protocol_hint: Arc::new(AtomicU8::new(0)),
                    h3_failures: Arc::new(AtomicU32::new(0)),
                    h3_last_failure_ms: Arc::new(AtomicU64::new(0)),
                    h3_backoff_until_ms: Arc::new(AtomicU64::new(0)),
                    h2_last_rebuild_ms: Arc::new(AtomicU64::new(0)),
                    h3_last_rebuild_ms: Arc::new(AtomicU64::new(0)),
                    h2_client: Arc::new(Default::default()),
                    h2_target_addr: Arc::new(Default::default()),
                })
            }
            "tls" => {
                let host = url.host_str().unwrap_or_else(|| {
                    exit_with_error(&format!(
                        "DoT URL '{}' must include a host",
                        server_address_str
                    ))
                }).to_string();
                let port = url.port().unwrap_or(853);
                Upstream::Dot(DotUpstream { host, port })
            }
            "http" => {
                exit_with_error("Only https://, h3://, or tls:// URLs are supported for upstreams");
            }
            _ => {
                exit_with_error(&format!(
                    "Unsupported URL scheme '{}' for upstream",
                    url.scheme()
                ));
            }
        }
    } else {
        let server_address = server_address_str
            .to_socket_addrs()
            .unwrap_or_else(|e| {
                exit_with_error(&format!(
                    "Invalid server address '{}': {}",
                    server_address_str, e
                ))
            })
            .next()
            .unwrap_or_else(|| {
                exit_with_error(&format!(
                    "Cannot resolve server address '{}'",
                    server_address_str
                ))
            });
        Upstream::Dns(server_address)
    };

    // Parse local bind address
    globals.local_bind_address = match matches.get_one::<String>("local_bind_address") {
        Some(address) => address.parse().unwrap_or_else(|e| {
            exit_with_error(&format!("Invalid local bind address '{}': {}", address, e))
        }),
        None => match globals.upstream {
            Upstream::Dns(SocketAddr::V4(_)) => {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            }
            Upstream::Dns(SocketAddr::V6(s)) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                s.flowinfo(),
                s.scope_id(),
            )),
            Upstream::Doh(_) | Upstream::Dot(_) => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        },
    };

    // Parse bootstrap DNS addresses
    globals.bootstrap_dns = match matches.get_many::<String>("bootstrap") {
        Some(values) => values
            .map(|value| {
                value.parse().unwrap_or_else(|e| {
                    exit_with_error(&format!("Invalid bootstrap address '{}': {}", value, e))
                })
            })
            .collect(),
        None => vec![],
    };

    // Parse path
    globals.path = matches
        .get_one::<String>("path")
        .expect("path has a default value")
        .to_string();
    if !globals.path.starts_with('/') {
        globals.path = format!("/{}", globals.path);
    }

    // Parse max_clients
    let max_clients_str = matches
        .get_one::<String>("max_clients")
        .expect("max_clients has a default value");
    globals.max_clients = max_clients_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!("Invalid max clients '{}': {}", max_clients_str, e))
    });

    // Parse timeout
    let timeout_str = matches
        .get_one::<String>("timeout")
        .expect("timeout has a default value");
    let timeout_secs: u64 = timeout_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid timeout '{}': {}", timeout_str, e)));
    globals.timeout = Duration::from_secs(timeout_secs);

    // Parse max_concurrent_streams
    let max_concurrent_str = matches
        .get_one::<String>("max_concurrent")
        .expect("max_concurrent has a default value");
    globals.max_concurrent_streams = max_concurrent_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Invalid max concurrent streams '{}': {}",
            max_concurrent_str, e
        ))
    });

    // Parse min_ttl
    let min_ttl_str = matches
        .get_one::<String>("min_ttl")
        .expect("min_ttl has a default value");
    globals.min_ttl = min_ttl_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid min TTL '{}': {}", min_ttl_str, e)));

    // Parse max_ttl
    let max_ttl_str = matches
        .get_one::<String>("max_ttl")
        .expect("max_ttl has a default value");
    globals.max_ttl = max_ttl_str
        .parse()
        .unwrap_or_else(|e| exit_with_error(&format!("Invalid max TTL '{}': {}", max_ttl_str, e)));

    // Parse err_ttl
    let err_ttl_str = matches
        .get_one::<String>("err_ttl")
        .expect("err_ttl has a default value");
    globals.err_ttl = err_ttl_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!("Invalid error TTL '{}': {}", err_ttl_str, e))
    });
    globals.keepalive = !matches.get_flag("disable_keepalive");
    globals.disable_post = matches.get_flag("disable_post");
    globals.allow_odoh_post = matches.get_flag("allow_odoh_post");
    globals.enable_ecs = matches.get_flag("enable_ecs");

    // Parse ECS prefix lengths
    let ecs_prefix_v4_str = matches
        .get_one::<String>("ecs_prefix_v4")
        .expect("ecs_prefix_v4 has a default value");
    globals.ecs_prefix_v4 = ecs_prefix_v4_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Invalid ECS IPv4 prefix '{}': {}",
            ecs_prefix_v4_str, e
        ))
    });

    let ecs_prefix_v6_str = matches
        .get_one::<String>("ecs_prefix_v6")
        .expect("ecs_prefix_v6 has a default value");
    globals.ecs_prefix_v6 = ecs_prefix_v6_str.parse().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "Invalid ECS IPv6 prefix '{}': {}",
            ecs_prefix_v6_str, e
        ))
    });

    #[cfg(feature = "tls")]
    {
        globals.tls_cert_path = matches
            .get_one::<String>("tls_cert_path")
            .map(PathBuf::from);
        globals.tls_cert_key_path = matches
            .get_one::<String>("tls_cert_key_path")
            .map(PathBuf::from)
            .or_else(|| globals.tls_cert_path.clone());
    }

    match matches.get_one::<String>("hostname") {
        Some(hostname) => {
            let public_addresses: Vec<&String> = matches
                .get_many::<String>("public_address")
                .map(|values| values.collect())
                .unwrap_or_default();

            let public_port = matches.get_one::<String>("public_port").map(|port| {
                port.parse::<u16>().unwrap_or_else(|e| {
                    exit_with_error(&format!("Invalid public port '{}': {}", port, e))
                })
            });

            if public_addresses.is_empty() {
                // No public addresses specified, generate stamps without IP
                let mut doh_builder =
                    dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string());
                if let Some(port) = public_port {
                    doh_builder = doh_builder.with_port(port);
                }
                match doh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate DoH stamp: {}", e),
                }

                let mut odoh_builder = dnsstamps::ODoHTargetBuilder::new(
                    hostname.to_string(),
                    globals.path.to_string(),
                );
                if let Some(port) = public_port {
                    odoh_builder = odoh_builder.with_port(port);
                }
                match odoh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over Oblivious DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate ODoH stamp: {}", e),
                }
            } else {
                // Generate stamps for each public address
                for public_address in &public_addresses {
                    let mut doh_builder =
                        dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string())
                            .with_address(public_address.to_string());
                    if let Some(port) = public_port {
                        doh_builder = doh_builder.with_port(port);
                    }
                    match doh_builder.serialize() {
                        Ok(stamp) => println!(
                            "Test DNS stamp to reach [{}] via [{}] over DoH: [{}]",
                            hostname, public_address, stamp
                        ),
                        Err(e) => eprintln!(
                            "Warning: Failed to generate DoH stamp for {}: {}",
                            public_address, e
                        ),
                    }
                }
                println!(); // Empty line for readability

                // ODoH stamps don't support IP addresses, so we generate just one
                let mut odoh_builder = dnsstamps::ODoHTargetBuilder::new(
                    hostname.to_string(),
                    globals.path.to_string(),
                );
                if let Some(port) = public_port {
                    odoh_builder = odoh_builder.with_port(port);
                }
                match odoh_builder.serialize() {
                    Ok(stamp) => println!(
                        "Test DNS stamp to reach [{}] over Oblivious DoH: [{}]\n",
                        hostname, stamp
                    ),
                    Err(e) => eprintln!("Warning: Failed to generate ODoH stamp: {}", e),
                }
            }

            println!("Check out https://dnscrypt.info/stamps/ to compute the actual stamps.\n")
        }
        _ => {
            println!(
            "Please provide a fully qualified hostname (-H <hostname> command-line option) to get \
             test DNS stamps for your server.\n"
        );
        }
    }
}
