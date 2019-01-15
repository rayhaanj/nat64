#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern crate libc;
extern crate pnet_packet;
extern crate pnetlink;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use libc::{close, ioctl};
use std::os::unix::prelude::AsRawFd;
use std::os::unix::io::RawFd;
use std::io;
use std::io::Read;
use std::error::Error;
use std::io::Write;
use pnet_packet::Packet;
use pnet_packet::PacketSize;

mod translator;

const TUN_PATH: &'static str = "/dev/net/tun";

pub struct InterfaceName {
    name: [i8; 16],
}

impl InterfaceName {
    fn ifname(s: &[u8]) -> Option<[u8; 16]> {
        if s.len() > 16 {
            return None;
        } else {
            let mut res = [0u8; 16];
            res[..s.len()].copy_from_slice(s);
            return Some(res);
        }
    }

    fn new(name: String) -> Result<Self, String> {
        let c = match CString::new(name) {
            Err(reason) => return Err(String::from(reason.description())),
            Ok(c) => c,
        };
        let b = match InterfaceName::ifname(c.as_bytes_with_nul()) {
            None => return Err(String::from("Interface name too long")),
            Some(b) => b,
        };
        Ok(InterfaceName {
            name: unsafe { std::mem::transmute::<[u8; 16], [i8; 16]>(b) },
        })
    }
}

pub struct OwnedFd {
    fd: RawFd,
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if unsafe { close(self.fd) } < 0 {
            print!("Error closing file descriptor: {}", io::Error::last_os_error());
        }
    }
}

// TunnelIface represents a TUN interface.
pub struct TunnelIface {
    dev: File,
    sock: OwnedFd,
    if_name: InterfaceName,
}

impl TunnelIface {
    unsafe fn create_iface(name: [i8; 16], fd: std::os::unix::io::RawFd) -> Result<(), String> {
        let mut ifr: ifreq = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 { ifrn_name: name },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_flags: IFF_TUN as i16,
            },
        };
        if ioctl(fd, CONST_TUNSETIFF, &mut ifr) < 0 {
            return Err(format!("failed to create tunnel interface: {}",
                io::Error::last_os_error()));
        }
        Ok(())
    }

    // Open a socket to configure the TUN interface.
    // Returns (socket on the tunnel interface, interface index).
    fn create_sock(name: [i8; 16]) -> Result<(OwnedFd, libc::c_int), String> {
        let sock: OwnedFd = OwnedFd {
            fd: unsafe { libc::socket(AF_PACKET as i32, __socket_type_SOCK_DGRAM as i32, 0) }
                as RawFd,
        };
        if sock.fd < 0 {
            return Err(String::from(format!(
                "failed to create AF_PACKET socket: {}",
                io::Error::last_os_error()
            )));
        }
        let mut req: ifreq = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 { ifrn_name: name },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_ivalue: 0 as i32,
            },
        };
        let res = unsafe { ioctl(sock.fd, SIOCGIFINDEX as u64, &mut req) };
        if res < 0 {
            return Err(String::from(format!(
                "failed to get interface index: {}",
                io::Error::last_os_error()
            )));
        }

        return Ok((sock, unsafe { req.ifr_ifru.ifru_ivalue }));
    }

    fn ifup(&self) -> Result<(), String> {
        // Check if the interface is already up.
        let mut ifr: ifreq = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 {
                ifrn_name: self.if_name.name,
            },
            ifr_ifru: ifreq__bindgen_ty_2 { ifru_flags: 0 },
        };
        if unsafe { ioctl(self.sock.fd, CONST_SIOCSIFFLAGS, &mut ifr) } < 0 {
            return Err(String::from(format!(
                "failed getting flags for interface: {}",
                io::Error::last_os_error()
            )));
        }
        if unsafe { (ifr.ifr_ifru.ifru_flags & IFF_UP as i16 & IFF_RUNNING as i16) } != 0 {
            return Ok(()); // Early return if the interface is already up.
        }
        // Set the interface state to up.
        unsafe { ifr.ifr_ifru.ifru_flags |= IFF_UP as i16 | IFF_RUNNING as i16 };
        if unsafe { ioctl(self.sock.fd, CONST_SIOCSIFFLAGS, &mut ifr) } < 0 {
            return Err(String::from(format!(
                "failed setting flags on interface: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub fn new(name: String) -> Result<Self, String> {
        let name = InterfaceName::new(name).unwrap();
        let dev = match OpenOptions::new().read(true).write(true).open(TUN_PATH) {
            Err(reason) => {
                return Err(String::from(format!(
                    "failed to open {}: {}",
                    TUN_PATH, reason
                )))
            }
            Ok(dev) => dev,
        };

        // Create the interface.
        unsafe { TunnelIface::create_iface(name.name, dev.as_raw_fd())?; }

        // Create a control socket.
        let (sock, _) = match TunnelIface::create_sock(name.name) {
            Err(reason) => return Err(String::from(format!("failed to create socket: {}", reason))),
            Ok((sock, ifidx)) => (sock, ifidx),
        };

        Ok(TunnelIface {
            dev: dev,
            if_name: name,
            sock: sock,
        })
    }
}

fn main() {
    let mut tif: TunnelIface = TunnelIface::new(String::from("tayl0r")).unwrap();
    tif.ifup().unwrap();

    let mut xlator = translator::HMNat64::new("64:ff9b::/96", "10.1.2.0/24").unwrap();

    let mut buf: [u8; 1600] = [0; 1600];
    loop {
        let len = tif.dev.read(&mut buf).unwrap();
        // Try to parse the packet.
        if buf[4] == 0x60 {
            // IPv6 packet in.
            let mut ip6_pkt = pnet_packet::ipv6::MutableIpv6Packet::new(&mut buf[4..len]).unwrap();
            println!("from: {}, to: {}", ip6_pkt.get_source(), ip6_pkt.get_destination());
            if !xlator.is_to_prefix(ip6_pkt.get_destination()) {
                println!("skipping");
                continue;
            }
            // FIXME: 1500 byte buffer.
            let mut buf: [u8;1500] = [0u8; 1500];
            let out_pkt = match xlator.process_v6(&mut ip6_pkt, &mut buf).map_err(|e| format!("error: {:?}", e)) {
                Err(reason) => { println!("err: {:?}", reason); continue; },
                Ok(pkt) => pkt,
            };
            let pkt_len = out_pkt.packet_size();
            println!("to write: {:?}", &(out_pkt.packet()[..pkt_len]));
            let mut merged = Vec::new();
            merged.extend_from_slice(&[0u8; 4]);
            merged.extend_from_slice(&out_pkt.packet()[..pkt_len]);
            let len = tif.dev.write(&merged);
            println!("written {:?} bytes to dev", len);
        } else if buf[4] == 0x40 {
            // IPv4 packet in.
            let ip4_pkt = pnet_packet::ipv4::Ipv4Packet::new(&buf[4..len]).unwrap();
            println!("from {}, to {}", ip4_pkt.get_source(), ip4_pkt.get_destination());
        }
    }
}
