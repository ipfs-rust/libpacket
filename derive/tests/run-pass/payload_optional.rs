use libpacket_core::Packet;
use libpacket_derive::Packet;

#[derive(Debug, Packet)]
pub struct PayloadOptional {
    #[length = "2"]
    header: Vec<u8>,
    remaining: Vec<u8>,
}

fn main() {
    let packet = [0x9d, 0x7f, 0x3e, 0x7d];
    let p = PayloadOptionalPacket::new(&packet[..]).unwrap();
    assert_eq!(p.payload(), &[]);
    assert_eq!(p.get_header_raw(), &packet[..2]);
    assert_eq!(p.get_remaining_raw(), &packet[2..]);
}
