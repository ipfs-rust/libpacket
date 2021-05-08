#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::udp::UdpPacket;
use libpacket::Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(udp) = UdpPacket::new(data) {
        for b in udp.payload().iter() {
            drop(*b);
        }
    }
});
