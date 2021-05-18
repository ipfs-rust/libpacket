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
    #[length = "0"]
    #[payload]
    payload1: Vec<u8>,
    #[payload]
    payload2: Vec<u8>,
}

fn main() {}