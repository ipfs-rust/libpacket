use libpacket_derive::Packet;

#[inline]
fn varint_length(first_byte: u8) -> usize {
    let prefix = first_byte >> 6;
    let length = (1 << prefix) - 1;
    length
}

#[inline]
fn varint(first_byte: u8, rest: &[u8]) -> usize {
    let mut length = (first_byte & 0x3f) as u64;
    for v in rest {
        length = (length << 8) + *v as u64;
    }
    length as usize
}

#[derive(Debug, Packet)]
pub struct Varint {
    varint_1: u8,
    #[length = "varint_length(varint_1)"]
    varint_2: Vec<u8>,
    #[payload]
    //#[length_fn = "initial_payload_length"]
    payload: Vec<u8>,
}

fn main() {
    let packet = [0x9d, 0x7f, 0x3e, 0x7d];
    let p = VarintPacket::new(&packet[..]).unwrap();
    let v = varint(p.get_varint_1(), p.get_varint_2_raw());
    assert_eq!(v, 494_878_333);
}
