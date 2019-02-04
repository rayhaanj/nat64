#![allow(dead_code)]
extern crate ipnetwork;
extern crate pnet_packet;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use translator::pnet_packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use translator::pnet_packet::icmpv6::{Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use translator::pnet_packet::ip::IpNextHeaderProtocols;
use translator::pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use translator::pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use translator::pnet_packet::{MutablePacket, PacketSize};
use translator::pnet_packet::{icmp, icmpv6, ipv4, tcp, udp, Packet};

#[derive(Debug)]
pub enum Xlat6to4Error {
    TTLExceeded,
    BufferTooSmall,
    Other(String),
}

#[derive(Debug)]
pub enum Xlat4to6Error {
    TTLExceeded,
    BufferTooSmall,
    DestinationUnreachable,
    Other(String),
}

fn u8_to_u16(a: u8, b: u8) -> u16 {
    (a as u16) << 8 | b as u16
}

enum PrefixLen {
    P32,
    P40,
    P48,
    P56,
    P64,
    P96,
}

// HMNat64 implements a Host Mapped NAT64, which only records mappings between hosts
// and their corresponding v4 addresses. This is a compromise between complete
// statelessness where machines on the v6 side need special addresses and a fully
// stateful NAT which needs to keep per flow state.
pub struct HMNat64 {
    n64_prefix: ipnetwork::Ipv6Network,
    pfx_len: PrefixLen,
    ip4_range: ipnetwork::Ipv4Network,

    // Stores a mapping of v6 side client to v4 source address.
    xlat_table: HashMap<Ipv6Addr, Ipv4Addr>,
    xlat_inv_table: HashMap<Ipv4Addr, Ipv6Addr>,
    used_v4: HashSet<Ipv4Addr>,
}

impl HMNat64 {
    pub fn new(v6_prefix: &str, v4_range: &str) -> Result<Self, String> {
        let p = match ipnetwork::Ipv6Network::from_str(v6_prefix) {
            Err(reason) => return Err(format!("failed to parse prefix: {}", reason)),
            Ok(ip6net) => ip6net,
        };

        let pfx_len: PrefixLen = match p.prefix() {
            32 => PrefixLen::P32,
            40 => PrefixLen::P40,
            48 => PrefixLen::P48,
            56 => PrefixLen::P56,
            64 => PrefixLen::P64,
            96 => PrefixLen::P96,
            _ => {
                return Err(format!(
                    "invalid prefix length: {}, must be one of 32, 40, 48, 56, 64, or 96",
                    p.prefix()
                ));
            }
        };

        let v4 = match ipnetwork::Ipv4Network::from_str(v4_range) {
            Err(reason) => return Err(format!("failed to parse prefix: {}", reason)),
            Ok(ip4net) => ip4net,
        };

        Ok(HMNat64 {
            n64_prefix: p,
            pfx_len: pfx_len,
            ip4_range: v4,
            xlat_table: HashMap::new(),
            xlat_inv_table: HashMap::new(),
            used_v4: HashSet::new(),
        })
    }

    pub fn process_v4<'p>(
        &mut self,
        pkt: &mut MutableIpv4Packet,
        buf: Box<Vec<u8>>
    ) -> Result<Ipv6Packet<'p>, Xlat4to6Error> {
        let mut response: MutableIpv6Packet<'p> = MutableIpv6Packet::owned(*buf).ok_or(Xlat4to6Error::BufferTooSmall)?;
        let v6dst: Ipv6Addr = *self.get_v6addr_for_host(pkt.get_destination()).ok_or(Xlat4to6Error::DestinationUnreachable)?;
        let v6src: Ipv6Addr = self.v4_to_v6(pkt.get_source());

        response.set_version(6);
        response.set_source(v6src);
        response.set_destination(v6dst);

        let hop_lim = pkt.get_ttl() - 1;
        if hop_lim == 0 {
            return Err(Xlat4to6Error::TTLExceeded);
        }
        response.set_hop_limit(hop_lim);

        let data_offset: usize = 40;
        let inpt_len: usize = (pkt.get_total_length() - 20) as usize;

        match pkt.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => {
                response.set_next_header(IpNextHeaderProtocols::Icmpv6);
                let old_payload = IcmpPacket::new(pkt.payload()).unwrap();
                let size = HMNat64::icmp4_to_icmp6(
                    &v6src,
                    &v6dst,
                    &old_payload,
                    &mut response.packet_mut()[data_offset as usize .. (data_offset + inpt_len)])?;
                response.set_payload_length(size);
            }
            IpNextHeaderProtocols::Tcp => {
                response.set_next_header(IpNextHeaderProtocols::Tcp);
                let mut tcp_pkt = tcp::MutableTcpPacket::new(pkt.payload_mut()).unwrap();
                let sum = pnet_packet::tcp::ipv6_checksum_adv(
                    &tcp_pkt.to_immutable(),
                    &[0u8; 0],
                    &v6src,
                    &v6dst);
                tcp_pkt.set_checksum(sum);
                response.set_payload_length(tcp_pkt.packet().len() as u16);
                response.set_payload(tcp_pkt.packet());
            }
            IpNextHeaderProtocols::Udp => {
                response.set_next_header(IpNextHeaderProtocols::Udp);
                let mut udp_pkt = udp::MutableUdpPacket::new(pkt.payload_mut()).unwrap();
                let sum = pnet_packet::udp::ipv6_checksum_adv(
                    &udp_pkt.to_immutable(),
                    &[0u8; 0],
                    &v6src,
                    &v6dst);
                udp_pkt.set_checksum(sum);
                response.set_payload_length(udp_pkt.packet().len() as u16);
                response.set_payload(udp_pkt.packet());
            }
            _ => {
                response.set_payload_length(pkt.payload().len() as u16);
                response.set_payload(pkt.payload());
                response.set_next_header(pkt.get_next_level_protocol());
            }
        }

        Ok(response.consume_to_immutable())
    }

    // Takes an incoming v6 packet and returns the translated v4 packet.
    pub fn process_v6<'p>(
        &mut self,
        pkt: &mut MutableIpv6Packet,
        buf: Box<Vec<u8>>,
    ) -> Result<Ipv4Packet<'p>, Xlat6to4Error> {
        let mut response: MutableIpv4Packet<'p> =
            pnet_packet::ipv4::MutableIpv4Packet::owned(*buf).ok_or(Xlat6to4Error::BufferTooSmall)?;
        let v4src: Ipv4Addr = self
            .get_v4addr_for_host(pkt.get_source())
            .map_err(|e| Xlat6to4Error::Other(e))?;
        let v4dst: Ipv4Addr = self.v6_to_v4(pkt.get_destination());

        response.set_version(4);
        response.set_header_length(5);
        response.set_dscp(pkt.get_traffic_class());
        response.set_identification(0); // TODO: Check what this should be.
        response.set_fragment_offset(0);

        // Decrement and check the TTL.
        let ttl = pkt.get_hop_limit() - 1;
        if ttl == 0 {
            // TODO: Should return ICMP Time Exceeded message to the sender.
            return Err(Xlat6to4Error::TTLExceeded);
        }
        response.set_ttl(ttl);

        let ihl_v4: u16 = 20; // Offset to write data to in the output v4 packet. 

        match pkt.get_next_header() {
            IpNextHeaderProtocols::Icmpv6 => {
                response.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                let old_payload = Icmpv6Packet::new(pkt.payload()).unwrap();
                let size = HMNat64::icmp6_to_icmp4(&old_payload, &mut response.packet_mut()[ihl_v4 as usize ..])?;
                response.set_total_length((ihl_v4 as u16) + size);
            }
            IpNextHeaderProtocols::Tcp => {
                let mut tcp_pkt = tcp::MutableTcpPacket::new(pkt.payload_mut()).unwrap();
                let sum = pnet_packet::tcp::ipv4_checksum_adv(
                    &tcp_pkt.to_immutable(),
                    &[0u8; 0],
                    &v4src,
                    &v4dst,
                );
                tcp_pkt.set_checksum(sum);
                response.set_total_length(ihl_v4 + tcp_pkt.packet().len() as u16);
                response.set_payload(tcp_pkt.packet());
                response.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            }
            IpNextHeaderProtocols::Udp => {
                let mut udp_pkt = udp::MutableUdpPacket::new(pkt.payload_mut()).unwrap();
                let sum = pnet_packet::udp::ipv4_checksum_adv(
                    &udp_pkt.to_immutable(),
                    &[0u8; 0],
                    &v4src,
                    &v4dst,
                );
                udp_pkt.set_checksum(sum);
                response.set_total_length(ihl_v4 + udp_pkt.packet().len() as u16);
                response.set_payload(udp_pkt.packet());
                response.set_next_level_protocol(IpNextHeaderProtocols::Udp)
            }
            _ => {
                // If the protocol is unknown leave the inner payload alone and forward.
                response.set_total_length(ihl_v4 + pkt.payload().len() as u16);
                response.set_payload(pkt.payload());
                response.set_next_level_protocol(pkt.get_next_header());
            }
        }

        // Ipv4 flags: [ZERO, DF, MF]
        if response.get_total_length() <= 1280 {
            response.set_flags(0);
        } else {
            response.set_flags(2);
        }

        response.set_source(v4src);
        response.set_destination(v4dst);
        let sum = ipv4::checksum(&response.to_immutable());
        response.set_checksum(sum);
        Ok(response.consume_to_immutable())
    }

    // TODO: check if the ICMPv6 packet is too long, that might break the buffer we pass in
    // because I'm not sure if pnet is handling that somwehere.
    fn icmp6_to_icmp4(pkt: &Icmpv6Packet, buf: &mut [u8]) -> Result<u16, Xlat6to4Error> {
        let mut result = MutableIcmpPacket::new(buf).unwrap();

        match pkt.get_icmpv6_type() {
            Icmpv6Types::EchoRequest => HMNat64::handle_icmp_echo_request_6to4(pkt, &mut result),
            Icmpv6Types::EchoReply => HMNat64::handle_icmp_echo_reply_6to4(pkt, &mut result),
            Icmpv6Types::DestinationUnreachable => {
                HMNat64::handle_icmp_dest_unreach_6to4(pkt, &mut result)
            }
            t => return Err(Xlat6to4Error::Other(format!("unsupported ICMP type: {:?}", t)));
        };

        let sum = icmp::checksum(&result.to_immutable());
        result.set_checksum(sum);
        // packet_size() returns only the ICMP header length...
        Ok((result.packet_size() + pkt.payload().len()) as u16)
    }

    fn icmp4_to_icmp6(
        src: &Ipv6Addr,
        dst: &Ipv6Addr,
        pkt: &IcmpPacket,
        buf: &mut [u8]) -> Result<u16, Xlat4to6Error> {
        let mut result = MutableIcmpv6Packet::new(buf).unwrap();
        match pkt.get_icmp_type() {
            IcmpTypes::EchoRequest => HMNat64::handle_icmp_echo_request_4to6(pkt, &mut result),
            IcmpTypes::EchoReply => HMNat64::handle_icmp_echo_reply_4to6(pkt, &mut result),
            IcmpTypes::DestinationUnreachable => HMNat64::handle_icmp_dest_unreach_4to6(pkt, &mut result),
            t => {
                return Err(Xlat4to6Error::Other(format!("Unsupported ICMP type: {:?}", t)));
            }
        }
        let size = (result.packet_size() + pkt.payload().len()) as u16;
        let sum = icmpv6::checksum(&result.to_immutable(), src, dst);
        result.set_checksum(sum);
        Ok((result.packet_size() + pkt.payload().len()) as u16)
    }

    fn handle_icmp_echo_request_6to4(inpt: &Icmpv6Packet, out: &mut MutableIcmpPacket) {
        out.set_icmp_type(IcmpTypes::EchoRequest);
        out.set_payload(inpt.payload());
    }

    fn handle_icmp_echo_request_4to6(inpt: &IcmpPacket, out: &mut MutableIcmpv6Packet) {
        out.set_icmpv6_type(Icmpv6Types::EchoRequest);
        out.set_payload(inpt.payload());
    }

    fn handle_icmp_echo_reply_6to4(inpt: &Icmpv6Packet, out: &mut MutableIcmpPacket) {
        out.set_icmp_type(IcmpTypes::EchoReply);
        out.set_payload(inpt.payload());
    }

    fn handle_icmp_echo_reply_4to6(inpt: &IcmpPacket, out: &mut MutableIcmpv6Packet) {
        out.set_icmpv6_type(Icmpv6Types::EchoReply);
        out.set_payload(inpt.payload());
    }

    fn handle_icmp_dest_unreach_6to4(inpt: &Icmpv6Packet, out: &mut MutableIcmpPacket) {
        out.set_icmp_type(IcmpTypes::DestinationUnreachable);
        out.set_payload(inpt.payload());
    }

    fn handle_icmp_dest_unreach_4to6(inpt: &IcmpPacket, out: &mut MutableIcmpv6Packet) {
        out.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        out.set_payload(inpt.payload());
    }

    // is_to_prefix returns true if the destination address is to the translation
    // range serviced by this XLAT.
    pub fn is_to_prefix(&self, dest: Ipv6Addr) -> bool {
        self.n64_prefix.contains(dest)
    }

    // get_v4addr_for_host returns an ipv4 address to use as the source address
    // for communications from a given IPv6 host.
    fn get_v4addr_for_host(&mut self, src: Ipv6Addr) -> Result<Ipv4Addr, String> {
        match self.xlat_table.get(&src) {
            Some(v6addr) => return Ok(*v6addr),
            None => {} // fallthrough.
        }
        // Need to get a new address out of the v4 pool.
        match self.ip4_range.nth((self.used_v4.len() + 1) as u32) {
            Some(v4addr) => {
                self.xlat_table.insert(src, v4addr);
                self.xlat_inv_table.insert(v4addr, src);
                self.used_v4.insert(v4addr);
                return Ok(v4addr);
            }
            None => return Err(String::from("ipv4 address space depleted!")),
        }
    }

    fn get_v6addr_for_host(&self, dst: Ipv4Addr) -> Option<&Ipv6Addr> {
        println!("xlat inv table is: {:?}, query is: {:?} \n", self.xlat_inv_table, dst);
        self.xlat_inv_table.get(&dst)
    }

    // Register mapping inserts an association between an IPv6 address and an IPv4 address.
    fn register_mapping(&mut self, src: Ipv6Addr, dst: Ipv4Addr) {
        self.xlat_table.insert(src, dst);
        self.xlat_inv_table.insert(dst, src);
    }

    // v4_to_v6 embeds the IPv4 address into the IPv6 prefix.
    fn v4_to_v6(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let ipv4_octets = ipv4.octets();
        let prefix_octets = self.n64_prefix.network().octets();
        //     |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
        match self.pfx_len {
            // |32|     prefix    |v4(32)         | u | suffix                    |
            PrefixLen::P32 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                u8_to_u16(ipv4_octets[2], ipv4_octets[3]),
                u8_to_u16(0, prefix_octets[9]),
                u8_to_u16(prefix_octets[10], prefix_octets[11]),
                u8_to_u16(prefix_octets[12], prefix_octets[13]),
                u8_to_u16(prefix_octets[14], prefix_octets[15]),
            ),
            // |40|     prefix        |v4(24)     | u |(8)| suffix                |
            PrefixLen::P40 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(prefix_octets[4], ipv4_octets[0]),
                u8_to_u16(ipv4_octets[1], ipv4_octets[2]),
                u8_to_u16(0, ipv4_octets[3]),
                u8_to_u16(prefix_octets[10], prefix_octets[11]),
                u8_to_u16(prefix_octets[12], prefix_octets[13]),
                u8_to_u16(prefix_octets[14], prefix_octets[15]),
            ),
            // |48|     prefix            |v4(16) | u | (16)  | suffix            |
            PrefixLen::P48 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(prefix_octets[4], prefix_octets[5]),
                u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                u8_to_u16(0, ipv4_octets[2]),
                u8_to_u16(ipv4_octets[3], prefix_octets[11]),
                u8_to_u16(prefix_octets[12], prefix_octets[13]),
                u8_to_u16(prefix_octets[14], prefix_octets[15]),
            ),
            // |56|     prefix                |(8)| u |  v4(24)   | suffix        |
            PrefixLen::P56 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(prefix_octets[4], prefix_octets[5]),
                u8_to_u16(prefix_octets[6], ipv4_octets[0]),
                u8_to_u16(0, ipv4_octets[1]),
                u8_to_u16(ipv4_octets[2], ipv4_octets[3]),
                u8_to_u16(prefix_octets[12], prefix_octets[13]),
                u8_to_u16(prefix_octets[14], prefix_octets[15]),
            ),
            // |64|     prefix                    | u |   v4(32)      | suffix    |
            PrefixLen::P64 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(prefix_octets[4], prefix_octets[5]),
                u8_to_u16(prefix_octets[6], prefix_octets[7]),
                u8_to_u16(0, ipv4_octets[0]),
                u8_to_u16(ipv4_octets[1], ipv4_octets[2]),
                u8_to_u16(ipv4_octets[3], prefix_octets[13]),
                u8_to_u16(prefix_octets[14], prefix_octets[15]),
            ),
            // |96|     prefix                                    |    v4(32)     |
            PrefixLen::P96 => Ipv6Addr::new(
                u8_to_u16(prefix_octets[0], prefix_octets[1]),
                u8_to_u16(prefix_octets[2], prefix_octets[3]),
                u8_to_u16(prefix_octets[4], prefix_octets[5]),
                u8_to_u16(prefix_octets[6], prefix_octets[7]),
                u8_to_u16(prefix_octets[8], prefix_octets[9]),
                u8_to_u16(prefix_octets[10], prefix_octets[11]),
                u8_to_u16(ipv4_octets[0], ipv4_octets[1]),
                u8_to_u16(ipv4_octets[2], ipv4_octets[3]),
            ),
        }
    }

    fn v6_to_v4(&self, ipv6: Ipv6Addr) -> Ipv4Addr {
        let ipv6_octets = ipv6.octets();
        match self.pfx_len {
            PrefixLen::P32 => Ipv4Addr::new(
                ipv6_octets[4],
                ipv6_octets[5],
                ipv6_octets[6],
                ipv6_octets[7],
            ),
            PrefixLen::P40 => Ipv4Addr::new(
                ipv6_octets[5],
                ipv6_octets[6],
                ipv6_octets[7],
                ipv6_octets[9],
            ),
            PrefixLen::P48 => Ipv4Addr::new(
                ipv6_octets[6],
                ipv6_octets[7],
                ipv6_octets[9],
                ipv6_octets[10],
            ),
            PrefixLen::P56 => Ipv4Addr::new(
                ipv6_octets[7],
                ipv6_octets[9],
                ipv6_octets[10],
                ipv6_octets[11],
            ),
            PrefixLen::P64 => Ipv4Addr::new(
                ipv6_octets[9],
                ipv6_octets[10],
                ipv6_octets[11],
                ipv6_octets[12],
            ),
            PrefixLen::P96 => Ipv4Addr::new(
                ipv6_octets[12],
                ipv6_octets[13],
                ipv6_octets[14],
                ipv6_octets[15],
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use translator::pnet_packet::icmpv6::{Icmpv6Type, Icmpv6Code};
    use translator::pnet_packet::icmp::{IcmpCode, IcmpType};
    use translator::pnet_packet::ip::IpNextHeaderProtocol;

    struct TranslateTestCase<'a> {
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        n64_prefix: &'a str,
    }

    struct PacketTestCase {
        ipv4: Box<Vec<u8>>,
        ipv6: Box<Vec<u8>>,
    }

    #[test]
    fn test_convert_u8_to_u16() {
        assert_eq!(0, u8_to_u16(0, 0));
        assert_eq!(514, u8_to_u16(2, 2));
        assert_eq!(32639, u8_to_u16(127, 127));
        assert_eq!(65535, u8_to_u16(255, 255));
    }

    #[test]
    fn test_addr_range() {
        let ipv6_subnet = ipnetwork::Ipv6Network::from_str("2001:db8::abc0/124").unwrap();
        let suffixes = vec![
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        let mut idx = 0;
        for addr in ipv6_subnet.iter() {
            let expected_address =
                ipnetwork::Ipv6Network::from_str(&format!("2001:db8::abc{}/128", suffixes[idx]))
                    .unwrap()
                    .network();
            idx += 1;
            assert_eq!(addr, expected_address);
        }
        assert_eq!(idx, 16);
    }

    #[test]
    fn test_addr_mappping() {
        let mut xlat = HMNat64::new("64:ff9b::/96", "10.0.0.0/28").unwrap();
        let ipv6_subnet = ipnetwork::Ipv6Network::from_str("2001:db8::abc0/124").unwrap();
        let ipv4_subnet = ipnetwork::Ipv4Network::from_str("10.0.0.0/28").unwrap();
        for (i, addr) in ipv6_subnet.iter().enumerate() {
            if i == 0 {
                continue; // Skip the network address 2001:db8::abc0/128.
            }
            let xlated = xlat.get_v4addr_for_host(addr).unwrap();
            let expected = ipv4_subnet.nth(i as u32).unwrap();
            assert_eq!(xlated, expected);
            let reverse: Ipv6Addr = *xlat.get_v6addr_for_host(xlated).unwrap();
            assert_eq!(reverse, addr);
        }
        match xlat.get_v4addr_for_host(Ipv6Addr::new(0x2001, 0xdb8, 0xcafe, 0xbabe, 0, 0, 0, 0)) {
            Ok(r) => panic!(format!("expected ipv4 depletion error but got Ok({})", r)),
            Err(_) => {}
        }
    }

    #[test]
    fn test_translate() {
        let tests = vec![
            TranslateTestCase {
                ipv4: Ipv4Addr::new(8, 8, 8, 8),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x808),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(0, 0, 0, 0),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(255, 255, 255, 255),
                ipv6: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xffff, 0xffff),
                n64_prefix: "64:ff9b::/96",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0xc000, 0x221, 0, 0, 0, 0),
                n64_prefix: "2001:db8::/32",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x1c0, 0x2, 0x21, 0, 0, 0),
                n64_prefix: "2001:db8:100::/40",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0xc000, 0x2, 0x2100, 0, 0),
                n64_prefix: "2001:db8:122::/48",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x3c0, 0x0, 0x221, 0, 0),
                n64_prefix: "2001:db8:122:300::/56",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x3c0, 0x0, 0x221, 0, 0),
                n64_prefix: "2001:db8:122:300::/56",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x344, 0xc0, 0x2, 0x2100, 0),
                n64_prefix: "2001:db8:122:344::/64",
            },
            TranslateTestCase {
                ipv4: Ipv4Addr::new(192, 0, 2, 33),
                ipv6: Ipv6Addr::new(0x2001, 0xdb8, 0x122, 0x344, 0, 0, 0xc000, 0x221),
                n64_prefix: "2001:db8:122:344::/96",
            },
        ];
        let client_subnet = "10.0.0.0/24";
        for test in tests {
            let translator = HMNat64::new(test.n64_prefix, client_subnet).unwrap();
            assert_eq!(test.ipv6, translator.v4_to_v6(test.ipv4));
            assert_eq!(test.ipv4, translator.v6_to_v4(test.ipv6));
        }
    }

    // Create an ICMPv4 packet with given type, code, payload.
    fn tmpl_icmp4(typ: IcmpType, code: IcmpCode, payload: &[u8]) -> Box<Vec<u8>> {
        // Size of ICMP v4 packet is 4 bytes + payload.
        let buf = vec![0u8; 4 + payload.len()];
        let mut icmp4_pkt = MutableIcmpPacket::owned(buf).unwrap();
        icmp4_pkt.set_icmp_type(typ);
        icmp4_pkt.set_icmp_code(code);
        icmp4_pkt.set_payload(payload);
        let checksum: u16 = icmp::checksum(&icmp4_pkt.to_immutable());
        icmp4_pkt.set_checksum(checksum);
        Box::new(icmp4_pkt.packet().to_vec())
    }

    // Create an ICMPv6 packet with given type, code and payload.
    fn tmpl_icmpv6(
        ipsrc: Ipv6Addr,
        ipdst: Ipv6Addr,
        typ: Icmpv6Type,
        code: Icmpv6Code,
        payload: &[u8],
    ) -> Box<Vec<u8>> {
        let buf = vec![0u8; 4 + payload.len()];
        let mut icmpv6_pkt = MutableIcmpv6Packet::owned(buf).unwrap();
        icmpv6_pkt.set_icmpv6_type(typ);
        icmpv6_pkt.set_icmpv6_code(code);
        icmpv6_pkt.set_payload(payload);
        let checksum: u16 = icmpv6::checksum(&icmpv6_pkt.to_immutable(), &ipsrc, &ipdst);
        icmpv6_pkt.set_checksum(checksum);
        Box::new(icmpv6_pkt.packet().to_vec())
    }

    #[derive(Debug)]
    enum AddrPair {
        Ipv4(Ipv4Addr, Ipv4Addr),
        Ipv6(Ipv6Addr, Ipv6Addr),
    }

    fn tmpl_tcp(
        ip_pair: AddrPair,
        src_port: u16,
        dst_port: u16,
        payload: &[u8]
    ) -> Box<Vec<u8>> {
        let buf = vec![0u8; 24 + payload.len()];
        let mut tcp_pkt = tcp::MutableTcpPacket::owned(buf).unwrap();
        tcp_pkt.set_source(src_port);
        tcp_pkt.set_destination(dst_port);
        tcp_pkt.set_payload(payload);
        match ip_pair {
            AddrPair::Ipv4(src, dst) => {
                let checksum: u16 = tcp::ipv4_checksum(&tcp_pkt.to_immutable(), &src, &dst);
                tcp_pkt.set_checksum(checksum);
            },
            AddrPair::Ipv6(src, dst) => {
                let checksum: u16 = tcp::ipv6_checksum(&tcp_pkt.to_immutable(), &src, &dst);
                tcp_pkt.set_checksum(checksum);
            }
        }
        Box::new(tcp_pkt.packet().to_vec())
    }

    fn tmpl_udp(
        ip_pair: AddrPair,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Box<Vec<u8>> {
        let buf = vec![0u8; 8 + payload.len()];
        let mut udp_pkt = udp::MutableUdpPacket::owned(buf).unwrap();
        udp_pkt.set_source(src_port);
        udp_pkt.set_destination(dst_port);
        udp_pkt.set_payload(payload);
        match ip_pair {
            AddrPair::Ipv4(src, dst) => {
                let checksum: u16 = udp::ipv4_checksum(&udp_pkt.to_immutable(), &src, &dst);
                udp_pkt.set_checksum(checksum);
            }
            AddrPair::Ipv6(src, dst) => {
                let checksum: u16 = udp::ipv6_checksum(&udp_pkt.to_immutable(), &src, &dst);
                udp_pkt.set_checksum(checksum);
            }
        }
        Box::new(udp_pkt.packet().to_vec())
    }

    // Wrap an IP payload with an IP header.
    fn wrap_iphdr(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ttl: u8,
        next: IpNextHeaderProtocol,
        payload: &[u8],
    ) -> Box<Vec<u8>> {
        let buf = vec![0u8; 20 + payload.len()];
        let mut ip4_pkt = MutableIpv4Packet::owned(buf).unwrap();
        ip4_pkt.set_version(4);
        ip4_pkt.set_source(src);
        ip4_pkt.set_destination(dst);
        ip4_pkt.set_header_length(5);
        ip4_pkt.set_total_length(20 + payload.len() as u16);
        ip4_pkt.set_ttl(ttl);
        ip4_pkt.set_next_level_protocol(next);
        ip4_pkt.set_payload(payload);
        let checksum: u16 = ipv4::checksum(&ip4_pkt.to_immutable());
        ip4_pkt.set_checksum(checksum);
        Box::new(ip4_pkt.packet().to_vec())
    }

    fn wrap_ip6hdr(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_lim: u8,
        next: IpNextHeaderProtocol,
        payload: &[u8],
    ) -> Box<Vec<u8>> {
        let buf = vec![0u8; 40 + payload.len()];
        let mut ip6_pkt = MutableIpv6Packet::owned(buf).unwrap();
        ip6_pkt.set_version(6);
        ip6_pkt.set_source(src);
        ip6_pkt.set_destination(dst);
        ip6_pkt.set_hop_limit(hop_lim);
        ip6_pkt.set_next_header(next);
        ip6_pkt.set_payload_length(payload.len() as u16);
        ip6_pkt.set_payload(payload);
        Box::new(ip6_pkt.packet().to_vec())
    }

    #[test]
    fn test_v4_to_v6() {
        let client_v4 = Ipv4Addr::new(10, 0, 0, 1);
        let client_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xcafe);
        let target_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let target_v6 = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x808, 0x808);
        let cafebeef = vec![0xca, 0xfe, 0xbe, 0xef];
        let tests: Vec<PacketTestCase> = vec![
            PacketTestCase {
                ipv6: wrap_ip6hdr(target_v6, client_v6, 254, IpNextHeaderProtocols::Icmpv6,
                    &*tmpl_icmpv6(target_v6, client_v6, icmpv6::Icmpv6Types::EchoRequest,
                        icmpv6::ndp::Icmpv6Codes::NoCode, &cafebeef)),
                ipv4: wrap_iphdr(target_v4, client_v4, 255, IpNextHeaderProtocols::Icmp,
                    &*tmpl_icmp4(icmp::IcmpTypes::EchoRequest, 
                        icmp::echo_request::IcmpCodes::NoCode, &cafebeef)),
            },
            PacketTestCase {
                ipv6: wrap_ip6hdr(target_v6, client_v6, 254, IpNextHeaderProtocols::Tcp,
                    &*tmpl_tcp(AddrPair::Ipv6(target_v6, client_v6), 42869, 443, &cafebeef)),
                ipv4: wrap_iphdr(target_v4, client_v4, 255, IpNextHeaderProtocols::Tcp,
                    &*tmpl_tcp(AddrPair::Ipv4(target_v4, client_v4), 42869, 443, &cafebeef))
            },
            PacketTestCase {
                ipv6: wrap_ip6hdr(target_v6, client_v6, 254, IpNextHeaderProtocols::Udp,
                    &*tmpl_udp(AddrPair::Ipv6(target_v6, client_v6), 3186, 443, &cafebeef)),
                ipv4: wrap_iphdr(target_v4, client_v4, 255, IpNextHeaderProtocols::Udp,
                    &*tmpl_udp(AddrPair::Ipv4(target_v4, client_v4), 3186, 443, &cafebeef))
            },
        ];
        let client_subnet = "10.0.0.0/24";
        for mut test in tests {
            let mut rbuf = Box::new(vec![0u8; 1500]);
            let mut translator = HMNat64::new("64:ff9b::/96", client_subnet).unwrap();
            translator.register_mapping(client_v6, client_v4);
            let four_to_six: Ipv6Packet = translator
                .process_v4(
                    &mut MutableIpv4Packet::new(&mut *test.ipv4).unwrap(),
                    rbuf,
                ).unwrap();
            assert_eq!(*test.ipv6, four_to_six.packet()[..40 + four_to_six.get_payload_length() as usize].to_vec());
        }
    }    

    #[test]
    fn test_v6_to_v4() {
        let client_v4 = Ipv4Addr::new(10, 0, 0, 1);
        let client_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xcafe);
        let target_v4 = Ipv4Addr::new(8, 8, 8, 8);
        let target_v6 = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x808, 0x808);
        let cafebeef = vec![0xca, 0xfe, 0xbe, 0xef];
        let tests: Vec<PacketTestCase> = vec![
            PacketTestCase {
                ipv6: wrap_ip6hdr(client_v6, target_v6, 255, IpNextHeaderProtocols::Icmpv6,
                    &*tmpl_icmpv6(client_v6, target_v6, icmpv6::Icmpv6Types::EchoRequest,
                        icmpv6::ndp::Icmpv6Codes::NoCode, &cafebeef)),
                ipv4: wrap_iphdr(client_v4, target_v4, 254, IpNextHeaderProtocols::Icmp,
                    &*tmpl_icmp4(icmp::IcmpTypes::EchoRequest, 
                        icmp::echo_request::IcmpCodes::NoCode, &cafebeef)),
            },
            PacketTestCase {
                ipv6: wrap_ip6hdr(client_v6, target_v6, 255, IpNextHeaderProtocols::Tcp,
                    &*tmpl_tcp(AddrPair::Ipv6(client_v6, target_v6), 42869, 443, &cafebeef)),
                ipv4: wrap_iphdr(client_v4, target_v4, 254, IpNextHeaderProtocols::Tcp,
                    &*tmpl_tcp(AddrPair::Ipv4(client_v4, target_v4), 42869, 443, &cafebeef))
            },
            PacketTestCase {
                ipv6: wrap_ip6hdr(client_v6, target_v6, 255, IpNextHeaderProtocols::Udp,
                    &*tmpl_udp(AddrPair::Ipv6(client_v6, target_v6), 3186, 443, &cafebeef)),
                ipv4: wrap_iphdr(client_v4, target_v4, 254, IpNextHeaderProtocols::Udp,
                    &*tmpl_udp(AddrPair::Ipv4(client_v4, target_v4), 3186, 443, &cafebeef))
            }
        ];
        let client_subnet = "10.0.0.0/24";
        for mut test in tests {
            let mut rbuf = Box::new(vec![0u8; 1500]);
            let mut translator = HMNat64::new("64:ff9b::/96", client_subnet).unwrap();
            let six_to_four: Ipv4Packet = translator
                .process_v6(
                    &mut MutableIpv6Packet::new(&mut *test.ipv6).unwrap(),
                    rbuf,
                )
                .unwrap();
            assert_eq!(*test.ipv4, six_to_four.packet()[..six_to_four.get_total_length() as usize].to_vec());
        }
    }
}
