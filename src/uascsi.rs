#![allow(unused_macros)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
use crate::types::*;
use crate::usbmon::XferPacket;
use crate::Packet;
use crate::PrimitiveValues;
use std::fmt;
use std::mem::transmute;

#[derive(Debug)]
pub enum UASPacket<'pkt> {
    Cmd(CommandPacket<'pkt>),
    Sns(SensePacket<'pkt>),
    Rsp(ResponsePacket<'pkt>),
    TskMng(TaskManagementPacket<'pkt>),
    RdRdy(ReadReadyPacket<'pkt>),
    WrRdy(WriteReadyPacket<'pkt>),
}

#[derive(Packet)]
pub struct TaskManagement {
    iu_id: u8,
    reserved: u8,
    tag: u16be,
    reserved2: u1,
    task_to_be_managed: u16be,
    #[length = "8"]
    logical_unit_number: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct Command {
    iu_id: u8,
    reserved: u8,
    tag: u16be,
    reserved2: u1,
    command_priority: u4,
    task_attribute: u3,
    ras: u8,
    reserved3: u8,
    lun: u16be,
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct Sense {
    iu_id: u8,
    reserved: u8,
    tag: u16be,
    status_qualifier: u16be,
    status: u8,
    reserved2: u8,
    length: u8,
    // TODO: don't handle as payload maybe
    #[payload]
    sense_data: Vec<u8>,
}

#[derive(Packet)]
pub struct ReadReady {
    iu_id: u8,
    rsvd: u8,
    tag: u16be,
    // NOTE: payload empty
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct WriteReady {
    iu_id: u8,
    rsvd: u8,
    tag: u16be,
    // NOTE: payload empty
    #[payload]
    payload: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub struct Info((u8, u8, u8));

impl Info {
    pub fn new(a: u8, b: u8, c: u8) -> Info {
        Info((a, b, c))
    }
}

impl PrimitiveValues for Info {
    type T = (u8, u8, u8);
    fn to_primitive_values(&self) -> Self::T {
        let tup = &self.0;
        (tup.0, tup.1, tup.2)
    }
}

#[derive(Packet)]
pub struct Response {
    iu_id: u8,
    reserved: u8,
    tag: u16be,
    #[construct_with(u8, u8, u8)]
    response_information: Info,
    response_code: u8,
    // NOTE: payload empty
    #[payload]
    payload: Vec<u8>,
}

impl<'pkt> UASPacket<'pkt> {
    pub fn new(src: &'pkt [u8]) -> Option<Self> {
        use UASPacket::*;
        // [1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        let uas = match src.get(0)? {
            0x01 => Cmd(CommandPacket::new(src)?),
            0x03 => Sns(SensePacket::new(src)?),
            0x04 => Rsp(ResponsePacket::new(src)?),
            0x05 => TskMng(TaskManagementPacket::new(src)?),
            0x06 => RdRdy(ReadReadyPacket::new(src)?),
            0x07 => WrRdy(WriteReadyPacket::new(src)?),
            _ => return None,
        };
        Some(uas)
    }
    pub fn is_command(&self) -> bool {
        use UASPacket::*;
        matches!(self, Cmd(_))
    }
    pub fn is_read_ready(&self) -> bool {
        use UASPacket::*;
        matches!(self, RdRdy(_))
    }
    pub fn payload(&self) -> &[u8] {
        use UASPacket::*;
        match self {
            Cmd(cmdpkt) => cmdpkt.payload(),
            RdRdy(rdpkt) => rdpkt.payload(),
            WrRdy(wrpkt) => wrpkt.payload(),
            Sns(snspkt) => snspkt.payload(),
            Rsp(rsppkt) => rsppkt.payload(),
            TskMng(tskmngpkt) => tskmngpkt.payload(),
            // _ => unreachable!(),
        }
    }
}
