// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libpacket_derive::Packet;

#[derive(Packet)]
pub struct PacketWithPayload {
    banana: u8,
    length: u8,
    header_length: u8,
    #[length = "length_fn(header_length)"]
    packet_option: Vec<PacketOption>,
    #[payload]
    payload: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct PacketOption {
    pineapple: u8,
    length: u8,
    #[length = "option_length_fn(length)"]
    #[payload]
    payload: Vec<u8>,
}

fn length_fn(header_length: u8) -> usize {
    header_length as usize - 2
}

fn option_length_fn(length: u8) -> usize {
    length as usize - 2
}

fn main() {
    let data = [1, 8, 5, 6, 3, 1, 9, 10];
    let packet = PacketWithPayloadPacket::new(&data[..]).unwrap();

    let packet_option = packet.get_packet_option();
    assert_eq!(packet_option.first().unwrap().pineapple, 6);
    assert_eq!(packet_option.first().unwrap().length, 3);
}
