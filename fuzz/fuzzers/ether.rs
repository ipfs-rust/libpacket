#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::ethernet::EthernetPacket;
use libpacket::Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(eth) = EthernetPacket::new(data) {
        let _s = eth.get_source();
        let _d = eth.get_destination();
        let _t = eth.get_ethertype();
        let pl = eth.payload();
        for b in pl.iter() {
            drop(*b);
        }
    }
});
