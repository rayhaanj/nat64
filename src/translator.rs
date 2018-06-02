use std::net::{Ipv4Addr, Ipv6Addr};

fn convert_u8_to_u16(a: u8, b: u8) -> u16 {
    (a as u16) << 8 | b as u16
}

fn translate_from_ipv4_to_ipv6(ipv4: Ipv4Addr) -> Ipv6Addr {
    let ipv4_octets = ipv4.octets();
    let first_half: u16 = convert_u8_to_u16(ipv4_octets[0], ipv4_octets[1]);
    let second_half: u16 = convert_u8_to_u16(ipv4_octets[2], ipv4_octets[3]);
    Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, first_half, second_half)
}

fn translate_from_ipv6_to_ipv4(ipv6: Ipv6Addr) -> Ipv4Addr {
    let ipv6_octets = ipv6.octets();
    Ipv4Addr::new(ipv6_octets[12], ipv6_octets[13], ipv6_octets[14],
                  ipv6_octets[15])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TranslateTestCase {
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
    }

    #[test]
    fn test_convert_u8_to_u16() {
        assert_eq!(0, convert_u8_to_u16(0, 0));
        assert_eq!(514, convert_u8_to_u16(2, 2));
        assert_eq!(32639, convert_u8_to_u16(127, 127));
        assert_eq!(65535, convert_u8_to_u16(255, 255));
    }

    #[test]
    fn test_translate() {
        let tests = vec![
            TranslateTestCase{
                ipv4: Ipv4Addr::new(8, 8, 8, 8),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x808),
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(0, 0, 0, 0),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
            },
            TranslateTestCase{
                ipv4: Ipv4Addr::new(255, 255, 255, 255),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xffff, 0xffff),
            },
        ];
        for test in tests {
            assert_eq!(test.ipv6, translate_from_ipv4_to_ipv6(test.ipv4));
            assert_eq!(test.ipv4, translate_from_ipv6_to_ipv4(test.ipv6));
        }
    }
}
