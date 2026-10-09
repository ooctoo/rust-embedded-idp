use std::net::Ipv4Addr;

use axum::http::Uri;

/// Trusted host configuration only. Never select this from request headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpTransportPolicy {
    #[default]
    Default,
    DevelopmentPrivateNetworkHttp,
}

impl HttpTransportPolicy {
    /// Checks the build gate even when the configured URL uses HTTPS.
    pub fn validate(self) -> Result<(), &'static str> {
        if self == Self::DevelopmentPrivateNetworkHttp
            && !cfg!(all(
                feature = "development-private-network-http",
                debug_assertions
            ))
        {
            return Err(
                "private network HTTP requires the development feature and debug assertions",
            );
        }
        Ok(())
    }

    /// Returns whether this URL requires restricted browser sessions.
    pub(crate) fn restricted(self, uri: &Uri) -> Result<bool, &'static str> {
        self.validate()?;
        let authority = uri.authority().ok_or("URL authority required")?;
        let host = uri
            .host()
            .filter(|value| !value.is_empty())
            .ok_or("URL host required")?;
        if authority.as_str().contains('@') {
            return Err("URL userinfo forbidden");
        }
        match uri.scheme_str() {
            Some("https") => Ok(false),
            Some("http") if matches!(host, "localhost" | "127.0.0.1" | "[::1]") => Ok(false),
            Some("http") if self == Self::DevelopmentPrivateNetworkHttp => {
                let ip: Ipv4Addr = host.parse().map_err(|_| "private IPv4 literal required")?;
                if ip.is_private() && ip.to_string() == host {
                    Ok(true)
                } else {
                    Err("private IPv4 literal required")
                }
            }
            _ => Err("URL requires HTTPS or explicit loopback HTTP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_loopbacks_and_rejects_private_http() {
        for uri in [
            "http://localhost",
            "http://127.0.0.1:3000",
            "http://[::1]",
            "https://example.com",
        ] {
            assert_eq!(
                HttpTransportPolicy::Default.restricted(&uri.parse().unwrap()),
                Ok(false)
            );
        }
        for uri in [
            "http://192.168.1.2",
            "http://127.1",
            "http://2130706433",
            "http://example.com",
            "https://a@b",
        ] {
            assert!(HttpTransportPolicy::Default
                .restricted(&uri.parse().unwrap())
                .is_err());
        }
    }

    #[test]
    fn development_is_gated_and_strictly_private() {
        let policy = HttpTransportPolicy::DevelopmentPrivateNetworkHttp;
        if !cfg!(all(
            feature = "development-private-network-http",
            debug_assertions
        )) {
            assert!(policy.validate().is_err());
            assert!(policy
                .restricted(&"https://example.com".parse().unwrap())
                .is_err());
            return;
        }
        for uri in [
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://172.31.255.254",
            "http://192.168.31.159:8080",
        ] {
            assert_eq!(policy.restricted(&uri.parse().unwrap()), Ok(true));
        }
        for uri in [
            "http://172.15.0.1",
            "http://172.32.0.1",
            "http://8.8.8.8",
            "http://0.0.0.0",
            "http://169.254.1.2",
            "http://[fd00::1]",
            "http://192.168.001.2",
            "http://3232235777",
            "http://0xc0a80101",
            "http://example.local",
            "http://192.168.1.2.evil.com",
        ] {
            assert!(policy.restricted(&uri.parse().unwrap()).is_err(), "{uri}");
        }
    }
}
