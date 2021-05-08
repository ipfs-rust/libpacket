#![no_main]

use libfuzzer_sys::fuzz_target;
use libpacket::tcp::TcpPacket;
use libpacket::Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(tcp) = TcpPacket::new(data) {
        let options = tcp.get_options_iter();
        for o in options {
            o.payload();
        }
        for b in tcp.payload().iter() {
            drop(*b);
        }
    }
});
