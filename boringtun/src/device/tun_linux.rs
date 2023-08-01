// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(target_os = "linux")]
pub fn errno() -> i32 {
    unsafe { *__errno_location() }
}

#[cfg(target_os = "android")]
pub fn errno() -> i32 {
    unsafe { *__errno() }
}

#[cfg(target_os = "linux")]
pub fn errno_str() -> String {
    let strerr = unsafe { strerror(*__errno_location()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

#[cfg(target_os = "android")]
pub fn errno_str() -> String {
    let strerr = unsafe { strerror(*__errno()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

const TUNGETIFF: u64 = 0x8004_54D2;
#[cfg(target_os = "linux")]
const TUNSETIFF: u64 = 0x4004_54ca;

#[cfg(target_os = "linux")]
pub const IFF_MULTI_QUEUE: c_int = 0x100;

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TunSocket {
    fn write(&self, src: &[u8]) -> usize {
        match unsafe { write(self.fd, src.as_ptr() as _, src.len()) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn new(name: &str) -> Result<TunSocket, Error> {
        // If the provided name appears to be a FD, use that.
        let provided_fd = name.parse::<i32>();
        if let Ok(fd) = provided_fd {
            return Ok(TunSocket {
                fd,
                name: name.to_string(),
            });
        }

        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd => fd,
        };

        #[cfg(target_os = "linux")]
        {
            let iface_name = name.as_bytes();
            let mut ifr = ifreq {
                ifr_name: [0; IFNAMSIZ],
                ifr_ifru: IfrIfru {
                    ifru_flags: (IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI) as _,
                },
            };

            if iface_name.len() >= ifr.ifr_name.len() {
                return Err(Error::InvalidTunnelName);
            }

            ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

            if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
                return Err(Error::IOCtl(errno_str()));
            }
        }

        let name = name.to_string();
        Ok(TunSocket { fd, name })
    }

    fn new_from_fd(fd: RawFd) -> Result<TunSocket, Error> {
        #[cfg(target_os = "linux")]
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_intval: 0 },
        };

        #[cfg(target_os = "android")]
        let ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_intval: 0 },
        };

        if unsafe { ioctl(fd, TUNGETIFF as _, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }
        let flags = unsafe { ifr.ifr_ifru.ifru_flags };
        if flags & IFF_TUN as c_short == 0 {
            return Err(Error::InvalidTunnelName);
        }
        let name = std::str::from_utf8(&ifr.ifr_name[..])
            .map_err(|_| Error::InvalidTunnelName)?
            .to_owned();

        #[cfg(target_os = "linux")]
        {
            ifr.ifr_ifru = IfrIfru {
                ifru_flags: (IFF_TUN | IFF_MULTI_QUEUE) as _,
            };
            if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
                return Err(Error::IOCtl(errno_str()));
            }
        }

        Ok(TunSocket { fd, name })
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let provided_fd = self.name.parse::<i32>();
        if provided_fd.is_ok() {
            return Ok(1500);
        }

        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd => fd,
        };

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU as _, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { read(self.fd, dst.as_mut_ptr() as _, dst.len()) } {
            -1 => Err(Error::IfaceRead(errno())),
            n => Ok(&mut dst[..n as usize]),
        }
    }
}
