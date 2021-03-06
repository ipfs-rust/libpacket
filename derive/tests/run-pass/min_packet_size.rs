// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libpacket_core::types::*;
use libpacket_derive::Packet;

#[derive(Packet)]
pub struct ByteAligned {
    banana: u8,
    #[payload]
    payload: Vec<u8>,
}


#[derive(Packet)]
pub struct ByteAlignedWithVariableLength {
    banana: u16be,
    #[length = "0"]
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct ByteAlignedWithVariableLengthAndPayload {
    banana: u32be,
    #[length = "0"]
    var_length: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct NonByteAligned {
    banana: u3,
    tomato: u5,
    #[payload]
    payload: Vec<u8>,
}


#[derive(Packet)]
pub struct NonByteAlignedWithVariableLength {
    banana: u11be,
    tomato: u21be,
    #[length = "0"]
    #[payload]
    payload: Vec<u8>,
}

#[derive(Packet)]
pub struct NonByteAlignedWithVariableLengthAndPayload {
    banana: u7,
    tomato: u9be,
    #[length = "0"]
    var_length: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

fn main() {
    assert_eq!(ByteAlignedPacket::minimum_packet_size(), 1);
    assert_eq!(ByteAlignedWithVariableLengthPacket::minimum_packet_size(),
               2);
    assert_eq!(ByteAlignedWithVariableLengthAndPayloadPacket::minimum_packet_size(),
               4);
    assert_eq!(NonByteAlignedPacket::minimum_packet_size(), 1);
    assert_eq!(NonByteAlignedWithVariableLengthPacket::minimum_packet_size(),
               4);
    assert_eq!(NonByteAlignedWithVariableLengthAndPayloadPacket::minimum_packet_size(),
               2);
}
