#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::ipv4::Ipv4Packet;
use libpacket::Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(ipv4) = Ipv4Packet::new(data) {
        let options = ipv4.get_options_raw();
        for o in options.iter() {
            drop(*o);
        }
        for b in ipv4.payload().iter() {
            drop(*b);
        }
    }
});
