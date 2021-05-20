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
pub struct PacketWithU16 {
    length: u8,
    #[length = "length"]
    data: Vec<u16be>,
    #[length = "(...).len()"]
    payload: Vec<u8>,
}

fn main() {

    // Test if we can add data to the u16be
    let mut packet = [0u8; 9];
    {
        let mut p = MutablePacketWithU16Packet::new(&mut packet[..]).unwrap();
        p.set_length(6);
        p.set_data(&vec![0x0001, 0x1223, 0x3ff4]);
        p.set_payload(&vec![0xff, 0xff]);
    }

    let ref_packet = [0x06 /* length */, 0x00, 0x01, 0x12, 0x23, 0x3f, 0xf4, 0xff, 0xff];

    assert_eq!(&ref_packet[..], &packet[..]);
}
