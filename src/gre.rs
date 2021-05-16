// Copyright (c) 2016 Robert Collins <robertc@robertcollins.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Minimal GRE Packet implementation: suitable for inspection not generation (e.g. checksum not
//! implemented).

use crate::{types::*, Packet};

/// GRE (Generic Routing Encapsulation) Packet.
///
/// See RFCs 1701, 2784, 2890, 7676, 2637
///
/// Current status of implementation:
///
/// - [RFC 1701](https://tools.ietf.org/html/rfc1701) except for source routing and checksums.
///   Processing a source routed packet will panic. Checksums are able to be inspected, but not
///   calculated or verified.
///
/// - [RFC 2784](https://tools.ietf.org/html/rfc2784) except for checksums (same as 1701 status).
///   Note that it is possible to generate noncompliant packets by setting any of the reserved bits
///   (but see 2890).
///
/// - [RFC 2890](https://tools.ietf.org/html/rfc2890) implemented.
///
/// - [RFC 7676](https://tools.ietf.org/html/rfc7676) has no packet changes - compliance is up to
///   the user.
///
/// - [RFC 2637](https://tools.ietf.org/html/rfc2637) not implemented.
///
/// Note that routing information from RFC 1701 is not implemented, packets
/// with `routing_present` true will currently cause a panic.
#[derive(Debug, Packet)]
pub struct Gre {
    pub checksum_present: u1,
    pub routing_present: u1,
    pub key_present: u1,
    pub sequence_present: u1,
    pub strict_source_route: u1,
    pub recursion_control: u3,
    pub zero_flags: u5,
    pub version: u3,
    pub protocol_type: u16be, // 0x800 for ipv4 [basically an ethertype
    #[length = "(checksum_present | routing_present) * 2"]
    pub checksum: Vec<U16BE>,
    #[length = "(checksum_present | routing_present) * 2"]
    pub offset: Vec<U16BE>,
    #[length = "key_present * 4"]
    pub key: Vec<U32BE>,
    #[length = "sequence_present * 4"]
    pub sequence: Vec<U32BE>,
    #[length = "if routing_present == 0 { 0 } else { unimplemented!() }"]
    pub routing: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

/// `u16be`, but we can't use that directly in a `Vec` :(
#[derive(Debug, Packet)]
pub struct U16BE {
    number: u16be,
    #[length = "0"]
    #[payload]
    unused: Vec<u8>,
}

/// `u32be`, but we can't use that directly in a `Vec` :(
#[derive(Debug, Packet)]
pub struct U32BE {
    number: u32be,
    #[length = "0"]
    #[payload]
    unused: Vec<u8>,
}

#[test]
fn gre_packet_test() {
    let mut packet = [0u8; 4];
    {
        let mut gre_packet = MutableGrePacket::new(&mut packet[..]).unwrap();
        gre_packet.set_protocol_type(0x0800);
        assert_eq!(gre_packet.payload().len(), 0);
    }

    let ref_packet = [
        0x00, /* no flags */
        0x00, /* no flags, version 0 */
        0x08, /* protocol 0x0800 */
        0x00,
    ];

    assert_eq!(&ref_packet[..], &packet[..]);
}

#[test]
fn gre_checksum_test() {
    let mut packet = [0u8; 8];
    {
        let mut gre_packet = MutableGrePacket::new(&mut packet[..]).unwrap();
        gre_packet.set_checksum_present(1);
        assert_eq!(gre_packet.payload().len(), 0);
        assert_eq!(gre_packet.get_checksum().len(), 1);
        assert_eq!(gre_packet.get_offset().len(), 1);
    }

    let ref_packet = [
        0x80, /* checksum on */
        0x00, /* no flags, version 0 */
        0x00, /* protocol 0x0000 */
        0x00, 0x00, /* 16 bits of checksum */
        0x00, 0x00, /* 16 bits of offset */
        0x00,
    ];

    assert_eq!(&ref_packet[..], &packet[..]);
}
