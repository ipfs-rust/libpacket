#![allow(unused_macros)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
use crate::types::*;
use crate::Packet;
use crate::PrimitiveValues;
use std::mem::transmute;
use std::fmt;
use crate::usbmon::XferPacket;

#[derive(Packet)]
pub struct MassStor {

}

impl<'pkt> MassStorPacket<'pkt> {
    pub fn from_xfer(xfer: XferPacket<'pkt>) -> Option<MassStorPacket<'pkt>> {
        todo!()
    }
}
