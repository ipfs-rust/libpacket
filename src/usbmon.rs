#![allow(unused_macros)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
use crate::types::*;
use crate::Packet;
use crate::PrimitiveValues;
use std::fmt;
use std::mem::transmute;

#[derive(Copy, Clone)]
pub struct Setup((u8, u8, u8, u8, u8, u8, u8, u8));

impl fmt::Debug for Setup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"Setup {:x?}", self.0)
    }
}

impl Setup {
    fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> Self {
        Setup((a, b, c, d, e, f, g, h))
    }
}

impl PrimitiveValues for Setup {
    type T = (u8, u8, u8, u8, u8, u8, u8, u8);
    fn to_primitive_values(&self) -> Self::T {
        let tup = &self.0;
        (tup.0, tup.1, tup.2, tup.3, tup.4, tup.5, tup.6, tup.7)
    }
}

macro_rules! display1 {
    ($id:ident) => {
        impl<'pkt> fmt::Display for $id<'pkt> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let ty = if self.get_ty() == 0x43 { 'C' } else { 'S' };
                let bus = self.get_busnum();
                let dev = self.get_devnum();
                let mut len = (self.get_len_cap() + 64).to_string();
                let epnum = self.get_epnum();
                let direc = if epnum & 0b1000_0000 == 1 {
                    "IN"
                } else {
                    "OUT"
                };
                let ep = epnum & 0b0000_1111;
                writeln!(f, "{:>10}{:>10}{:>10}{:>10}", "src", "dst", "len", "info")?;
                let addr1 = "host".to_string();
                let addr2 = format!("{bus}.{dev}.{ep}");
                let (mut src, mut dst) = if ty == 'S' {
                    (addr1, addr2)
                } else {
                    (addr2, addr1)
                };
                writeln!(
                    f,
                    "{:>10}{:>10}{:>10}{:>10} {}",
                    src, dst, len, "Control", "IN"
                )
            }
        }
    };
}

impl<'pkt> fmt::Display for UsbMonPacket<'pkt> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // writeln!(f,"              id ty xfer_type epnum devnum busnum flag_setup flag_data           ts_sec  ts_usec   status len len_cap setup interval start_frame")?;
        writeln!(f, "id: {:016x}", self.get_id())?;
        writeln!(
            f,
            "ty: {:02x} ({})",
            self.get_ty(),
            if self.get_ty() == 0x43 {
                "Complete"
            } else {
                "Submit"
            }
        )?;
        let xfer_ty = self.get_xfer_type();
        let xfer_prtty = match xfer_ty {
            0x02 => "Control",
            0x03 => "Bulk",
            _ => "",
        };
        writeln!(f, "xfer_type: {:02x} ({:>10})", xfer_ty, xfer_prtty)?;
        let epnum = self.get_epnum();
        let direc = if epnum & 0b1000_0000 == 0 {
            "IN"
        } else {
            "OUT"
        };
        let ep = epnum & 0b0000_1111;
        writeln!(
            f,
            "epnum: {:#02x?} {:>10}",
            epnum,
            format!("({} {})", direc, ep)
        )?;
        writeln!(
            f,
            "devnum: {:#02x} {:>10}",
            self.get_devnum(),
            self.get_devnum()
        )?;
        writeln!(
            f,
            "busnum: {:#04x} {:>10}",
            self.get_busnum(),
            self.get_busnum()
        )?;
        writeln!(f, "flag_setup: {:#02x}", self.get_flag_setup())?;
        writeln!(f, "flag_data: {:#02x}", self.get_flag_data())?;
        let secs = self.get_ts_sec();
        let t = std::time::Duration::from_secs(secs);
        writeln!(f, "ts_sec: {:#016x} ({:?})", secs, t)?;
        let usecs = self.get_ts_usec();
        let ut = std::time::Duration::from_micros(usecs as u64);
        writeln!(f, "ts_usec: {:#08x} ({:?})", usecs, ut)?;
        writeln!(f, "status: {:08x}", self.get_status())?;
        writeln!(f, "len: {:#08x}", self.get_len())?;
        writeln!(f, "len_cap: {:#08x}", self.get_len_cap())?;
        use crate::PrimitiveValues as _;
        writeln!(f, "setup: {:02x?}", self.get_setup().to_primitive_values())?;
        writeln!(f, "interval: {:#08x}", self.get_interval())?;
        writeln!(f, "start_frame: {:#08x}", self.get_start_frame())?;
        writeln!(f, "xfer_flags: {:#08x}", self.get_xfer_flags())?;
        writeln!(f, "ndesc: {:#08x}", self.get_ndesc())?;
        writeln!(f, "payload: {:#02x?}", self.payload())
    }
}
// display1!(CtlPacket);
// display1!(BlkPacket);
// display1!(InterrPacket);
// display1!(IsochPacket);

// Intermediate Packet to extract transfer type
#[derive(Clone, Packet)]
pub struct UsbMon {
    pub id: u64le,
    pub ty: u8,
    pub xfer_type: u8,
    pub epnum: u8,
    pub devnum: u8,
    pub busnum: u16le,
    pub flag_setup: u8,
    pub flag_data: u8,
    pub ts_sec: u64le,
    pub ts_usec: u32le,
    pub status: u32le,
    pub len: u32le,
    pub len_cap: u32le,
    #[construct_with(u8, u8, u8, u8, u8, u8, u8, u8)]
    pub setup: Setup,
    pub interval: u32le,
    pub start_frame: u32le,
    pub xfer_flags: u32le,
    pub ndesc: u32le,
    #[payload]
    data: Vec<u8>,
}

impl<'pkt> UsbMonPacket<'pkt> {
    pub fn into_xfer_packet(self) -> Option<XferPacket<'pkt>> {
        use XferPacket::*;
        let setup = self.get_setup();
        let rf = unsafe { transmute(self.payload()) };
        let pkt = match self.get_xfer_type() {
            0x02 => Ctl(setup, rf),
            0x03 => Blk(setup, rf),
            _ => Isochr(setup, rf),
        };
        Some(pkt)
    }
    pub fn filter_flow(self, bus: u16le, dev: u8, ep: u8) -> Option<Self> {
        if bus != self.get_busnum() || dev != self.get_devnum() || ep != self.get_epnum() {
            None
        } else {
            Some(self)
        }
    }
}

#[derive(Debug, Packet)]
pub struct Device {
    length: u8,
    descriptor_type: u8,
    bcd_usb: u16le,
    class: u8,
    subclass: u8,
    protocol: u8,
    maxsize: u8,
    id_vendor: u16le,
    id_product: u16le,
    bcd_device: u16le,
    manufacturer: u8,
    product: u8,
    serial_number: u8,
    number_configurations: u8,
    #[payload]
    payload: Vec<u8>
}

#[derive(Clone, Debug, Packet)]
pub struct Config {
    length: u8,
    descriptor_type: u8,
    total_length: u16le,
    number_interfaces: u8,
    configuration_value: u8,
    configuration: u8,
    attributes: u8,
    max_power: u8,
    #[payload]
    payload: Vec<u8>
}

#[derive(Packet)]
pub struct Interface {
    length: u8,
    descriptor_type: u8,
    interface_number: u8,
    alternate_setting: u8,
    number_endpoints: u8,
    interface_class: u8,
    interface_subclass: u8,
    interface_protocol: u8,
    interface: u8,
    #[payload]
    payload: Vec<u8>
}

#[derive(Packet)]
pub struct Endpoint {
    length: u8,
    descriptor_type: u8,
    endpoint_address: u8,
    attributes: u8,
    maxsize: u16le,
    interval: u8,
    #[payload]
    payload: Vec<u8>,
}

#[derive(Debug)]
pub enum DescriptorPacket<'pkt> {
    Dev(DevicePacket<'pkt>),
    Cfg(ConfigPacket<'pkt>),
    If(InterfacePacket<'pkt>),
    Ep(EndpointPacket<'pkt>),
}

impl<'pkt> DescriptorPacket<'pkt> {
    pub fn is_device(&self) -> bool {
        use DescriptorPacket::*;
        matches!(self, Dev(_))
    }
    pub fn is_config(&self) -> bool {
        use DescriptorPacket::*;
        matches!(self, Cfg(_))
    }
    pub fn is_interface(&self) -> bool {
        use DescriptorPacket::*;
        matches!(self, If(_))
    }
    pub fn is_endpoint(&self) -> bool {
        use DescriptorPacket::*;
        matches!(self, Ep(_))
    }
    pub fn payload(&self) -> &[u8] {
        use DescriptorPacket::*;
        match self {
            Dev(dev) => {dev.payload()},
            Cfg(cfg) => {cfg.payload()},
            If(interf) => {interf.payload()},
            Ep(ep) => {ep.payload()},
        }
    }
    pub fn new(pkt: &'pkt [u8]) -> Option<Self> {
        use DescriptorPacket::*;
        let desc = match pkt.get(1)? {
            0x01 => Dev(DevicePacket::new(pkt)?),
            0x02 => Cfg(ConfigPacket::new(pkt)?),
            0x04 => If(InterfacePacket::new(pkt)?),
            0x05 => Ep(EndpointPacket::new(pkt)?),
            _ => {
                return None;
            }
        };
        Some(desc)
    }
    pub fn packet(&self) -> &[u8] {
        use DescriptorPacket::*;
        match self {
            Dev(pkt) => pkt.packet(),
            Cfg(pkt) => pkt.packet(),
            If(pkt) => pkt.packet(),
            Ep(pkt) => pkt.packet(),
        }
    }
}

// if setup is zero bytes, the packet is a reply
#[derive(Clone, Debug)]
pub enum XferPacket<'pkt> {
    Ctl(Setup, &'pkt [u8]),
    Blk(Setup, &'pkt [u8]),
    Isochr(Setup, &'pkt [u8]),
    Interr(Setup, &'pkt [u8]),
}

impl<'pkt> XferPacket<'pkt> {
    pub fn payload(&self) -> &[u8] {
        use XferPacket::*;
        match self {
            Ctl(_,ctl) => ctl,
            Blk(_,ctl) => ctl,
            Isochr(_,ctl) => ctl,
            Interr(_,ctl) => ctl,
        }
    }
    // pub fn is_control(&self) -> bool {
    //     use XferPacket::*;
    //     matches!(self, Ctl(_))
    // }
    // pub fn is_bulk(&self) -> bool {
    //     use XferPacket::*;
    //     matches!(self, Blk(_))
    // }
    // pub fn is_isochronous(&self) -> bool {
    //     use XferPacket::*;
    //     matches!(self, Isochr(_))
    // }
    // pub fn is_interrupt(&self) -> bool {
    //     use XferPacket::*;
    //     matches!(self, Interr(_))
    // }
    pub fn new(pkt: &'pkt [u8]) -> Option<Self> {
        UsbMonPacket::new(pkt)
            .map(|usbmon| usbmon.into_xfer_packet())
            .flatten()
    }
}
