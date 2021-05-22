#![allow(unused_imports)]
#![allow(dead_code)]
use crate::types::*;
use crate::Packet;
use crate::PrimitiveValues;

#[derive(Debug)]
pub enum Transfer<'pkt> {
    Ctl(CtlPacket<'pkt>),
    Bulk(BulkPacket<'pkt>),
    Isochr(IsochrPacket<'pkt>),
    Interr(InterrPacket<'pkt>),
}

impl Transfer<'_> {
    fn new(src: &[u8]) -> Option<Transfer<'_>> {
        use Transfer::*;
        if let Some(ctl) = CtlPacket::new(src) {
            return Some(Ctl(ctl));
        }
        if let Some(bulk) = BulkPacket::new(src) {
            return Some(Bulk(bulk));
        }
        if let Some(iso) = IsochrPacket::new(src) {
            return Some(Isochr(iso));
        }
        if let Some(interr) = InterrPacket::new(src) {
            return Some(Interr(interr));
        }
        None
    }
}

#[derive(Clone, Debug, Packet)]
pub struct Ctl {
    #[payload]
    payload: Vec<u8>,
}
#[derive(Clone, Debug, Packet)]
pub struct Bulk {
    #[payload]
    payload: Vec<u8>,
}
#[derive(Clone, Debug, Packet)]
pub struct Isochr {
    #[payload]
    payload: Vec<u8>,
}
#[derive(Clone, Debug, Packet)]
pub struct Interr {
    #[payload]
    payload: Vec<u8>,
}
