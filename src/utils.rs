// functions to verify the startup arguments as correct

use std::net::{SocketAddr, ToSocketAddrs};

use url::Url;

pub(crate) fn verify_sock_addr(arg_val: &str) -> Result<String, String> {
    match arg_val.parse::<SocketAddr>() {
        Ok(_addr) => Ok(arg_val.to_string()),
        Err(_) => Err(format!(
            "Could not parse \"{arg_val}\" as a valid socket address (with port)."
        )),
    }
}

pub(crate) fn verify_remote_server(arg_val: &str) -> Result<String, String> {
    match arg_val.to_socket_addrs() {
        Ok(mut addr_iter) => match addr_iter.next() {
            Some(_) => Ok(arg_val.to_string()),
            None => Err(format!(
                "Could not parse \"{arg_val}\" as a valid remote uri"
            )),
        },
        Err(err) => Err(format!("{err}")),
    }
}

pub(crate) fn verify_upstream(arg_val: &str) -> Result<String, String> {
    if arg_val.starts_with("http://")
        || arg_val.starts_with("https://")
        || arg_val.starts_with("h3://")
        || arg_val.starts_with("tls://")
    {
        let url = Url::parse(arg_val).map_err(|e| format!("Invalid URL: {e}"))?;
        match url.scheme() {
            "https" => {}
            "h3" => {}
            "tls" => {}
            "http" => {
                return Err(
                    "Only https://, h3://, or tls:// URLs are supported for upstreams".to_string(),
                )
            }
            _ => return Err(format!("Unsupported URL scheme '{}'", url.scheme())),
        }
        if url.host_str().is_none() {
            return Err("URL must include a host".to_string());
        }
        return Ok(arg_val.to_string());
    }
    verify_remote_server(arg_val)
}
