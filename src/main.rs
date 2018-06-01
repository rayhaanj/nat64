#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern crate libc;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::path::Path;
use libc::{close, ioctl};
use std::os::unix::prelude::AsRawFd;
use std::io;
use std::io::Read;

const TUN_PATH: &'static str = "/dev/net/tun";
const TUN_MTU: usize = 1500;

// TunnelIface represents a TUN interface.
pub struct TunnelIface {
    dev: File,
    sock: libc::c_int,
    ifidx: libc::c_int,
    if_name: [i8; 16],
}

impl TunnelIface {
    fn create_iface(name: [i8; 16], fd: std::os::unix::io::RawFd) -> libc::c_int {
        let mut ifr: ifreq = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 { ifrn_name: name },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_flags: IFF_TUN as i16,
            },
        };
        unsafe { ioctl(fd, CONST_TUNSETIFF, &mut ifr) }
    }

    // Create a socket that can send / recieve packets from the tunnel interface.
    // Returns (socket on the tunnel interface, interface index).
    unsafe fn create_sock(name: [i8; 16]) -> Result<(libc::c_int, libc::c_int), String> {
        let sock = libc::socket(AF_PACKET as i32, __socket_type_SOCK_DGRAM as i32, 0);
        if sock < 0 {
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
        let res = ioctl(sock, SIOCGIFINDEX as u64, &mut req);
        if res < 0 {
            close(sock);
            return Err(String::from(format!(
                "failed to get interface index: {}",
                io::Error::last_os_error()
            )));
        }

        return Ok((sock, req.ifr_ifru.ifru_ivalue));
    }

    fn ifup(&self) -> Result<libc::c_int, String> {
        // Check if the interface is already up.
        let mut ifr: ifreq = ifreq {
            ifr_ifrn: ifreq__bindgen_ty_1 { ifrn_name: self.if_name },
            ifr_ifru: ifreq__bindgen_ty_2 {
                ifru_flags: 0,
            },
        };
        if unsafe { ioctl(self.sock, CONST_SIOCSIFFLAGS, &mut ifr) } < 0 {
            return Err(String::from(format!("failed getting flags for interface: {}", io::Error::last_os_error())));
        }
        if unsafe { (ifr.ifr_ifru.ifru_flags & IFF_UP as i16 & IFF_RUNNING as i16) } != 0 {
            return Ok(0);
        }
        // Set the interface state to up.
        unsafe { ifr.ifr_ifru.ifru_flags |= IFF_UP as i16 | IFF_RUNNING as i16 } ;
        if unsafe { ioctl(self.sock, CONST_SIOCSIFFLAGS, &mut ifr) } < 0 {
            return Err(String::from(format!("failed setting flags on interface: {}", io::Error::last_os_error())));
        }
        Ok(0)
    }

    pub fn new(name: &str) -> Result<Self, String> {
        let name = CString::new(name).unwrap();
        let n: [i8; 16] = unsafe {
            std::mem::transmute::<[u8; 16], [i8; 16]>(ifname(name.to_bytes_with_nul()).unwrap())
        };

        let path = Path::new(TUN_PATH);
        let dev = match OpenOptions::new().read(true).write(true).open(&path) {
            Err(reason) => {
                return Err(String::from(format!(
                    "failed to open {}: {}",
                    TUN_PATH, reason
                )))
            }
            Ok(dev) => dev,
        };

        // Create the interface.
        if TunnelIface::create_iface(n, dev.as_raw_fd()) < 0 {
            return Err(String::from(format!(
                "failed to create tun interface: {}",
                io::Error::last_os_error()
            )));
        }

        // Create a socket.
        let (sock, ifidx) = match unsafe { TunnelIface::create_sock(n) } {
            Err(reason) => return Err(String::from(format!("failed to create socket: {}", reason))),
            Ok((sock, ifidx)) => (sock, ifidx),
        };

        return Ok(TunnelIface {
            dev: dev,
            if_name: n,
            sock: sock,
            ifidx: ifidx,
        });
    }
}

fn ifname(s: &[u8]) -> Option<[u8; 16]> {
    if s.len() > 16 {
        return None;
    } else {
        let mut res = [0u8; 16];
        for i in 0..s.len() {
            res[i] = s[i];
        }
        return Some(res);
    }
}

fn main() {
    let mut tif: TunnelIface = TunnelIface::new("tayl0r").unwrap();
    tif.ifup().unwrap();

    let mut buf: [u8; 1500] = [0; 1500];
    loop {
        let len = tif.dev.read(&mut buf).unwrap();
        println!("read packet of len {}:", len);
        for c in buf.iter() {
            print!("{:X} ", c);
        }
        print!("\n\n");
    }

}
