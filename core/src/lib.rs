// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Core types and traits used for defining packet dissectors.
#![deny(missing_docs)]

mod macaddr;
mod packet;
pub mod types;

pub use macaddr::{MacAddr, ETHER_ADDR_LEN};
pub use packet::{
    FromPacket, MutPacketData, MutablePacket, Packet, PacketData, PacketSize, PrimitiveValues,
};
