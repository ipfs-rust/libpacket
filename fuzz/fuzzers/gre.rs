#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::gre::GrePacket;

fuzz_target!(|data: &[u8]| {
    if let Some(gre) = GrePacket::new(data) {
        for b in gre.get_checksum_raw().iter() {
            drop(*b);
        }

        for b in gre.get_offset_raw().iter() {
            drop(*b);
        }

        for b in gre.get_key_raw().iter() {
            drop(*b);
        }

        for b in gre.get_sequence_raw().iter() {
            drop(*b);
        }

        for b in gre.get_routing_raw().iter() {
            drop(*b);
        }
    }
});
