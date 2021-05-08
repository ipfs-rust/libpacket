#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::vlan::VlanPacket;
use libpacket::Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(vlan) = VlanPacket::new(data) {
        for b in vlan.payload().iter() {
            drop(*b);
        }
    }
});
