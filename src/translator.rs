extern crate ipnetwork;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fn u8_to_u16(a: u8, b: u8) -> u16 {
    (a as u16) << 8 | b as u16
}

enum PrefixLen {
    p32, p40, p48, p56, p64, p96,
}

// StatelessNat64 implements a translator mechanism which does not keep state.
pub struct StatelessNat64 {
    n64_prefix: ipnetwork::Ipv6Network,
    pfx_len: PrefixLen,
}

impl StatelessNat64 {

    fn new(prefix: &str) -> Result<Self, String> {
        let p = match ipnetwork::Ipv6Network::from_str(prefix) {
            Err(reason) => return Err(format!("failed to parse prefix: {}", reason)),
            Ok(ipnet) => ipnet,
        };

        let pfx_len: PrefixLen = match p.prefix() {
            32 => PrefixLen::p32,
            40 => PrefixLen::p40,
            48 => PrefixLen::p48,
            56 => PrefixLen::p56,
            64 => PrefixLen::p64,
            96 => PrefixLen::p96,
            _ => return Err(format!("invalid prefix length: {}, must be one of 32, 40, 48, 56, 64, or 96", p.prefix())),
        };

        Ok(StatelessNat64{
            n64_prefix: p,
            pfx_len: pfx_len,
        })
    }

    // v4_to_v6 embeds the IPv4 address into the IPv6 prefix.
    fn v4_to_v6(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let ipv4_octets = ipv4.octets();
        let prefix_octets = self.n64_prefix.network().octets();
        //     |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
        match self.pfx_len {
            // |32|     prefix    |v4(32)         | u | suffix                    |
            PrefixLen::p32 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                             u8_to_u16(prefix_octets[2], prefix_octets[3]),
                             u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                             u8_to_u16(ipv4_octets[2], ipv4_octets[3]),
                             u8_to_u16(0, prefix_octets[9]),
                             u8_to_u16(prefix_octets[10], prefix_octets[11]),
                             u8_to_u16(prefix_octets[12], prefix_octets[13]),
                             u8_to_u16(prefix_octets[14], prefix_octets[15]))
            },
            // |40|     prefix        |v4(24)     | u |(8)| suffix                |
            PrefixLen::p40 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                              u8_to_u16(prefix_octets[2], prefix_octets[3]),
                              u8_to_u16(prefix_octets[4], ipv4_octets[0]),
                              u8_to_u16(ipv4_octets[1], ipv4_octets[2]),
                              u8_to_u16(0, ipv4_octets[3]),
                              u8_to_u16(prefix_octets[10], prefix_octets[11]),
                              u8_to_u16(prefix_octets[12], prefix_octets[13]),
                              u8_to_u16(prefix_octets[14], prefix_octets[15]))
            },
            // |48|     prefix            |v4(16) | u | (16)  | suffix            |
            PrefixLen::p48 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                              u8_to_u16(prefix_octets[2], prefix_octets[3]),
                              u8_to_u16(prefix_octets[4], prefix_octets[5]),
                              u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                              u8_to_u16(0, ipv4_octets[2]),
                              u8_to_u16(ipv4_octets[3], prefix_octets[11]),
                              u8_to_u16(prefix_octets[12], prefix_octets[13]),
                              u8_to_u16(prefix_octets[14], prefix_octets[15]))

            },
            // |56|     prefix                |(8)| u |  v4(24)   | suffix        |
            PrefixLen::p56 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                              u8_to_u16(prefix_octets[2], prefix_octets[3]),
                              u8_to_u16(prefix_octets[4], prefix_octets[5]),
                              u8_to_u16(prefix_octets[6], ipv4_octets[0]),
                              u8_to_u16(0, ipv4_octets[1]),
                              u8_to_u16(ipv4_octets[2], ipv4_octets[3]),
                              u8_to_u16(prefix_octets[12], prefix_octets[13]),
                              u8_to_u16(prefix_octets[14], prefix_octets[15]))
            },
            // |64|     prefix                    | u |   v4(32)      | suffix    |
            PrefixLen::p64 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                              u8_to_u16(prefix_octets[2], prefix_octets[3]),
                              u8_to_u16(prefix_octets[4], prefix_octets[5]),
                              u8_to_u16(prefix_octets[6], prefix_octets[7]),
                              u8_to_u16(0, ipv4_octets[0]),
                              u8_to_u16(ipv4_octets[1], ipv4_octets[2]),
                              u8_to_u16(ipv4_octets[3], prefix_octets[13]),
                              u8_to_u16(prefix_octets[14], prefix_octets[15]))
            }
            // |96|     prefix                                    |    v4(32)     |
            PrefixLen::p96 => {
                Ipv6Addr::new(u8_to_u16(prefix_octets[0], prefix_octets[1]),
                              u8_to_u16(prefix_octets[2], prefix_octets[3]),
                              u8_to_u16(prefix_octets[4], prefix_octets[5]),
                              u8_to_u16(prefix_octets[6], prefix_octets[7]),
                              u8_to_u16(prefix_octets[8], prefix_octets[9]),
                              u8_to_u16(prefix_octets[10], prefix_octets[11]),
                              u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                              u8_to_u16(ipv4_octets[2], ipv4_octets[3]))
            },
        }
    }

    fn v6_to_v4(&self, ipv6: Ipv6Addr) -> Ipv4Addr {
        let ipv6_octets = ipv6.octets();
        match self.pfx_len {
            PrefixLen::p32 => { Ipv4Addr::new(ipv6_octets[4], ipv6_octets[5],
                                            ipv6_octets[6], ipv6_octets[7]) }
            PrefixLen::p40 => { Ipv4Addr::new(ipv6_octets[5], ipv6_octets[6],
                                            ipv6_octets[7], ipv6_octets[9]) }
            PrefixLen::p48 => { Ipv4Addr::new(ipv6_octets[6], ipv6_octets[7],
                                            ipv6_octets[9], ipv6_octets[10]) }
            PrefixLen::p56 => { Ipv4Addr::new(ipv6_octets[7], ipv6_octets[9],
                                            ipv6_octets[10], ipv6_octets[11]) }
            PrefixLen::p64 => { Ipv4Addr::new(ipv6_octets[9], ipv6_octets[10],
                                            ipv6_octets[11], ipv6_octets[12]) }
            PrefixLen::p96 => { Ipv4Addr::new(ipv6_octets[12], ipv6_octets[13],
                                            ipv6_octets[14], ipv6_octets[15]) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TranslateTestCase<'a> {
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        n64_prefix: &'a str,
    }

    #[test]
    fn test_convert_u8_to_u16() {
        assert_eq!(0, u8_to_u16(0, 0));
        assert_eq!(514, u8_to_u16(2, 2));
        assert_eq!(32639, u8_to_u16(127, 127));
        assert_eq!(65535, u8_to_u16(255, 255));
    }

    #[test]
    fn test_translate() {
        let tests = vec![
            TranslateTestCase{
                ipv4: Ipv4Addr::new(8, 8, 8, 8),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x808),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(0, 0, 0, 0),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(255, 255, 255, 255),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xffff, 0xffff),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0xc000, 0x221, 0, 0, 0, 0),
                n64_prefix: "2001:db8::/32",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x1c0, 0x2, 0x21, 0, 0, 0),
                n64_prefix: "2001:db8:100::/40",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0xc000, 0x2, 0x2100, 0, 0),
                n64_prefix: "2001:db8:122::/48",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x3c0, 0x0, 0x221, 0, 0),
                n64_prefix: "2001:db8:122:300::/56",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x3c0, 0x0, 0x221, 0, 0),
                n64_prefix: "2001:db8:122:300::/56",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x344, 0xc0, 0x2, 0x2100, 0),
                n64_prefix: "2001:db8:122:344::/64",
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x344, 0, 0, 0xc000, 0x221),
                n64_prefix: "2001:db8:122:344::/96",
            },
        ];
        for test in tests {
            let translator = StatelessNat64::new(test.n64_prefix).unwrap();
            assert_eq!(test.ipv6, translator.v4_to_v6(test.ipv4));
            assert_eq!(test.ipv4, translator.v6_to_v4(test.ipv6));
        }
    }
}
