// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libpacket_derive::Packet;

#[derive(Packet)]
pub struct PacketWithPayload2 {
    banana: u8,
    #[payload(length_fn = "length_of_payload")]
    payload: Vec<u8>,
}

fn length_of_payload(_: &PacketWithPayload2Packet) -> usize {
    // FIXME
    unimplemented!()
}

fn main() {}
