//! `allowed_networks` (features/sql-browser.md §12): the addresses the plugin
//! may dial, checked on every address DNS returned, before connecting. The
//! connection is then made to that checked address, never re-resolved, so a
//! name cannot rebind between check and dial.
//!
//! A denied network wins over an allowed one. IPv4-mapped IPv6 addresses are
//! judged as the IPv4 address they carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// One CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let (ip, prefix) = s.trim().split_once('/').ok_or("expected address/prefix")?;
        let addr: IpAddr = ip.parse().map_err(|_| "not an IP address")?;
        let prefix: u8 = prefix.parse().map_err(|_| "bad prefix length")?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err("prefix length out of range");
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// `::ffff:a.b.c.d` is `a.b.c.d`; everything else is unchanged.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Whether `ip` may be dialled.
pub fn permitted(ip: IpAddr, allowed: &[Cidr], denied: &[Cidr]) -> bool {
    let ip = normalize(ip);
    if is_always_denied(ip) || denied.iter().any(|c| c.contains(ip)) {
        return false;
    }
    allowed.iter().any(|c| c.contains(ip))
}

/// Addresses no configuration can open: unspecified and broadcast.
fn is_always_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::UNSPECIFIED || v4 == Ipv4Addr::BROADCAST,
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED,
    }
}

/// Keep the resolved addresses that may be dialled, in DNS order. `Err`
/// names how many were refused when none is left.
pub fn filter(resolved: &[SocketAddr], allowed: &[Cidr], denied: &[Cidr]) -> Result<Vec<SocketAddr>, String> {
    let ok: Vec<SocketAddr> = resolved.iter().copied().filter(|a| permitted(a.ip(), allowed, denied)).collect();
    if ok.is_empty() {
        return Err(format!(
            "none of the {} address(es) the endpoint resolves to is in `allowed_networks` (or all are denied)",
            resolved.len()
        ));
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn defaults_allow_private_ranges_only() {
        let c = Config::default();
        let (a, d) = (c.allowed(), c.denied());
        for ok in ["10.1.2.3", "172.16.0.5", "172.31.255.255", "192.168.10.1", "fd00::1"] {
            assert!(permitted(ip(ok), &a, &d), "{ok}");
        }
        for no in [
            "127.0.0.1",
            "::1",
            "169.254.169.254",
            "fe80::1",
            "0.0.0.0",
            "8.8.8.8",
            "172.32.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!permitted(ip(no), &a, &d), "{no}");
        }
        assert!(permitted(ip("::ffff:10.0.0.1"), &a, &d), "a mapped private address is judged as IPv4");
    }

    #[test]
    fn deny_wins_even_over_an_allow_all() {
        let allow_all = [Cidr::parse("0.0.0.0/0").unwrap(), Cidr::parse("::/0").unwrap()];
        let denied = Config::default().denied();
        assert!(permitted(ip("203.0.113.9"), &allow_all, &denied));
        assert!(!permitted(ip("169.254.169.254"), &allow_all, &denied));
        assert!(!permitted(ip("0.0.0.0"), &allow_all, &[]), "unspecified is never dialled");
    }

    #[test]
    fn cidrs_parse_strictly() {
        for bad in ["10.0.0.0", "10.0.0.0/33", "::/129", "x/8", "10.0.0.0/-1", ""] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(ip("10.255.0.1")));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("11.0.0.1")));
        assert!(Cidr::parse("10.1.2.3/32").unwrap().contains(ip("10.1.2.3")));
    }

    #[test]
    fn filter_keeps_permitted_addresses_in_order() {
        let c = Config::default();
        let addrs: Vec<SocketAddr> = vec!["169.254.169.254:5432".parse().unwrap(), "10.0.0.7:5432".parse().unwrap()];
        assert_eq!(filter(&addrs, &c.allowed(), &c.denied()).unwrap(), vec![addrs[1]]);
        assert!(filter(&addrs[..1], &c.allowed(), &c.denied()).is_err());
    }
}
