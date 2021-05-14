use crate::{types::*, Packet, PrimitiveValues};
use std::convert::TryInto;

#[derive(Debug)]
pub enum QuicPacket<'a> {
    VersionNegotiation(VersionNegotiationPacket<'a>),
    Initial(InitialPacket<'a>),
    ZeroRtt(ZeroRttPacket<'a>),
    Handshake(HandshakePacket<'a>),
    Retry(RetryPacket<'a>),
    OneRtt(OneRttPacket<'a>),
}

impl<'a> QuicPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < 5 {
            None
        } else {
            let header_form = packet[0] & (1 << 7) > 0;
            let fixed_bit = packet[0] & (1 << 6) > 0;
            if fixed_bit && !header_form {
                Some(Self::OneRtt(OneRttPacket::new(packet)?))
            } else {
                if packet[1..5] == [0u8; 4] {
                    Some(Self::VersionNegotiation(VersionNegotiationPacket::new(
                        packet,
                    )?))
                } else {
                    match (LongPacketType::new((packet[0] >> 4) & 0b11), fixed_bit) {
                        (LongPacketTypes::Initial, true) => {
                            Some(Self::Initial(InitialPacket::new(packet)?))
                        }
                        (LongPacketTypes::ZeroRtt, true) => {
                            Some(Self::ZeroRtt(ZeroRttPacket::new(packet)?))
                        }
                        (LongPacketTypes::Handshake, true) => {
                            Some(Self::Handshake(HandshakePacket::new(packet)?))
                        }
                        (LongPacketTypes::Retry, true) => {
                            Some(Self::Retry(RetryPacket::new(packet)?))
                        }
                        _ => None,
                    }
                }
            }
        }
    }

    pub fn version(&self) -> Option<Version> {
        match self {
            Self::VersionNegotiation(_) => None,
            Self::Initial(packet) => Some(packet.get_version()),
            Self::ZeroRtt(packet) => Some(packet.get_version()),
            Self::Handshake(packet) => Some(packet.get_version()),
            Self::Retry(packet) => Some(packet.get_version()),
            Self::OneRtt(_) => None,
        }
    }

    pub fn token(&self) -> Option<Vec<u8>> {
        match self {
            Self::Initial(packet) => Some(packet.get_token()),
            _ => None,
        }
    }

    pub fn packet_number(&self) -> Option<u32> {
        match self {
            Self::VersionNegotiation(_) => None,
            Self::Initial(packet) => Some(packet.get_packet_number()),
            Self::ZeroRtt(packet) => Some(packet.get_packet_number()),
            Self::Handshake(packet) => Some(packet.get_packet_number()),
            Self::Retry(_) => None,
            Self::OneRtt(packet) => Some(packet.get_packet_number()),
        }
        .map(|mut pn| {
            pn.resize(4, 0);
            u32::from_be_bytes(pn.try_into().unwrap())
        })
    }

    pub fn dest_id(&self) -> Option<[u8; 20]> {
        let mut dest_id = match self {
            Self::VersionNegotiation(packet) => packet.get_dest_id(),
            Self::Initial(packet) => packet.get_dest_id(),
            Self::ZeroRtt(packet) => packet.get_dest_id(),
            Self::Handshake(packet) => packet.get_dest_id(),
            Self::Retry(packet) => packet.get_dest_id(),
            Self::OneRtt(packet) => packet.get_dest_id(),
        };
        dest_id.resize(20, 0);
        dest_id.try_into().ok()
    }

    pub fn src_id(&self) -> Option<[u8; 20]> {
        let mut src_id = match self {
            Self::VersionNegotiation(packet) => packet.get_src_id(),
            Self::Initial(packet) => packet.get_src_id(),
            Self::ZeroRtt(packet) => packet.get_src_id(),
            Self::Handshake(packet) => packet.get_src_id(),
            Self::Retry(packet) => packet.get_src_id(),
            Self::OneRtt(_) => return None,
        };
        src_id.resize(20, 0);
        src_id.try_into().ok()
    }

    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::VersionNegotiation(_) => return None,
            Self::Initial(packet) => Some(packet.payload()),
            Self::ZeroRtt(packet) => Some(packet.payload()),
            Self::Handshake(packet) => Some(packet.payload()),
            Self::Retry(_) => return None,
            Self::OneRtt(packet) => Some(packet.payload()),
        }
    }
}

impl<'a> std::fmt::Display for QuicPacket<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ty = match self {
            Self::VersionNegotiation(_) => "version-negotiation",
            Self::Initial(_) => "initial",
            Self::ZeroRtt(_) => "0rtt",
            Self::Handshake(_) => "handshake",
            Self::Retry(_) => "retry",
            Self::OneRtt(_) => "1rtt",
        };
        writeln!(f, "packet-type: {}", ty)?;
        if let Some(version) = self.version() {
            writeln!(f, "quic-version: {}", version)?;
        }
        if let Some(token) = self.token() {
            writeln!(f, "token: {:?}", token)?;
        }
        if let Some(pn) = self.packet_number() {
            writeln!(f, "packet-number: {}", pn)?;
        }
        if let Some(dest_id) = self.dest_id() {
            writeln!(f, "dest-id: {:?}", dest_id)?;
        }
        if let Some(src_id) = self.src_id() {
            writeln!(f, "src-id: {:?}", src_id)?;
        }
        if let Some(payload) = self.payload() {
            writeln!(f, "payload: {}", payload.len())?;
        }
        Ok(())
    }
}

#[derive(Debug, Packet)]
pub struct VersionNegotiation {
    #[construct_with(u1)]
    header_form: HeaderForm,
    unused: u7,
    version: u32be,
    dest_id_len: u8,
    #[length = "dest_id_len"]
    dest_id: Vec<u8>,
    src_id_len: u8,
    #[length = "src_id_len"]
    src_id: Vec<u8>,
    #[payload]
    supported_versions: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Initial {
    #[construct_with(u1)]
    header_form: HeaderForm,
    #[construct_with(u1)]
    fixed_bit: FixedBit,
    #[construct_with(u2)]
    long_packet_type: LongPacketType,
    reserved: u2,
    packet_number_len: u2,
    #[construct_with(u32be)]
    version: Version,
    dest_id_len: u8,
    #[length = "dest_id_len"]
    dest_id: Vec<u8>,
    src_id_len: u8,
    #[length = "src_id_len"]
    src_id: Vec<u8>,
    token_length_1: u8,
    #[length_fn = "initial_token_length_length"]
    token_length_2: Vec<u8>,
    #[length_fn = "initial_token_length"]
    token: Vec<u8>,
    payload_length_1: u8,
    #[length_fn = "initial_payload_length_length"]
    payload_length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[payload]
    #[length_fn = "initial_payload_length"]
    payload: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct ZeroRtt {
    #[construct_with(u1)]
    header_form: HeaderForm,
    #[construct_with(u1)]
    fixed_bit: FixedBit,
    #[construct_with(u2)]
    long_packet_type: LongPacketType,
    reserved: u2,
    packet_number_len: u2,
    #[construct_with(u32be)]
    version: Version,
    dest_id_len: u8,
    #[length = "dest_id_len"]
    dest_id: Vec<u8>,
    src_id_len: u8,
    #[length = "src_id_len"]
    src_id: Vec<u8>,
    payload_length_1: u8,
    #[length_fn = "zerortt_payload_length_length"]
    payload_length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[payload]
    #[length_fn = "zerortt_payload_length"]
    payload: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Handshake {
    #[construct_with(u1)]
    header_form: HeaderForm,
    #[construct_with(u1)]
    fixed_bit: FixedBit,
    #[construct_with(u2)]
    long_packet_type: LongPacketType,
    reserved: u2,
    packet_number_len: u2,
    #[construct_with(u32be)]
    version: Version,
    dest_id_len: u8,
    #[length = "dest_id_len"]
    dest_id: Vec<u8>,
    src_id_len: u8,
    #[length = "src_id_len"]
    src_id: Vec<u8>,
    payload_length_1: u8,
    #[length_fn = "handshake_payload_length_length"]
    payload_length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[payload]
    #[length_fn = "handshake_payload_length"]
    payload: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Retry {
    #[construct_with(u1)]
    header_form: HeaderForm,
    #[construct_with(u1)]
    fixed_bit: FixedBit,
    #[construct_with(u2)]
    long_packet_type: LongPacketType,
    unused: u4,
    #[construct_with(u32be)]
    version: Version,
    dest_id_len: u8,
    #[length = "dest_id_len"]
    dest_id: Vec<u8>,
    src_id_len: u8,
    #[length = "src_id_len"]
    src_id: Vec<u8>,
    #[payload]
    retry_token: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct OneRtt {
    header_form: u1,
    fixed_bit: u1,
    spin_bit: u1,
    reserved_bits: u2,
    key_phase: u1,
    packet_number_len: u2,
    #[length = "8"] // TODO: dest_id len
    dest_id: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

#[inline]
fn initial_token_length_length(p: &InitialPacket) -> usize {
    let prefix = p.get_token_length_1() >> 6;
    let length = (1 << prefix) - 1;
    length
}

#[inline]
fn initial_payload_length_length(p: &InitialPacket) -> usize {
    let prefix = p.get_payload_length_1() >> 6;
    let length = (1 << prefix) - 1;
    length
}

#[inline]
fn zerortt_payload_length_length(p: &ZeroRttPacket) -> usize {
    let prefix = p.get_payload_length_1() >> 6;
    let length = (1 << prefix) - 1;
    length
}

#[inline]
fn handshake_payload_length_length(p: &HandshakePacket) -> usize {
    let prefix = p.get_payload_length_1() >> 6;
    let length = (1 << prefix) - 1;
    length
}

#[inline]
fn initial_token_length(p: &InitialPacket) -> usize {
    let mut length = (p.get_token_length_1() & 0x3f) as u64;
    for v in p.get_token_length_2() {
        length = (length << 8) + v as u64;
    }
    length as usize
}

#[inline]
fn initial_payload_length(p: &InitialPacket) -> usize {
    let mut length = (p.get_payload_length_1() & 0x3f) as u64;
    for v in p.get_payload_length_2() {
        length = (length << 8) + v as u64;
    }
    length as usize
}

#[inline]
fn zerortt_payload_length(p: &ZeroRttPacket) -> usize {
    let mut length = (p.get_payload_length_1() & 0x3f) as u64;
    for v in p.get_payload_length_2() {
        length = (length << 8) + v as u64;
    }
    length as usize
}

#[inline]
fn handshake_payload_length(p: &HandshakePacket) -> usize {
    let mut length = (p.get_payload_length_1() & 0x3f) as u64;
    for v in p.get_payload_length_2() {
        length = (length << 8) + v as u64;
    }
    length as usize
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod HeaderForms {
    use super::HeaderForm;

    pub const Short: HeaderForm = HeaderForm(0);
    pub const Long: HeaderForm = HeaderForm(1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderForm(pub u8);

impl HeaderForm {
    /// Construct a new `FixedBit`.
    pub fn new(val: u8) -> Self {
        Self(val)
    }
}

impl PrimitiveValues for HeaderForm {
    type T = (u8,);
    fn to_primitive_values(&self) -> Self::T {
        (self.0,)
    }
}

impl std::fmt::Display for HeaderForm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            &HeaderForms::Short => "short",
            &HeaderForms::Long => "long",
            _ => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedBit(pub u8);

impl FixedBit {
    /// Construct a new `FixedBit`.
    pub fn new(val: u8) -> Self {
        Self(val)
    }
}

impl PrimitiveValues for FixedBit {
    type T = (u8,);
    fn to_primitive_values(&self) -> Self::T {
        (self.0,)
    }
}

impl std::fmt::Display for FixedBit {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self.0 {
            1 => "1",
            _ => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod LongPacketTypes {
    use super::LongPacketType;

    pub const Initial: LongPacketType = LongPacketType(0);
    pub const ZeroRtt: LongPacketType = LongPacketType(1);
    pub const Handshake: LongPacketType = LongPacketType(2);
    pub const Retry: LongPacketType = LongPacketType(3);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LongPacketType(pub u8);

impl LongPacketType {
    /// Construct a new `LongPacketType`.
    pub fn new(val: u8) -> Self {
        Self(val)
    }
}

impl PrimitiveValues for LongPacketType {
    type T = (u8,);
    fn to_primitive_values(&self) -> Self::T {
        (self.0,)
    }
}

impl std::fmt::Display for LongPacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            &LongPacketTypes::Initial => "initial",
            &LongPacketTypes::ZeroRtt => "0-rtt",
            &LongPacketTypes::Handshake => "handshake",
            &LongPacketTypes::Retry => "retry",
            _ => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u32);

impl Version {
    /// Construct a new `LongPacketType`.
    pub fn new(val: u32) -> Self {
        Self(val)
    }
}

impl PrimitiveValues for Version {
    type T = (u32be,);
    fn to_primitive_values(&self) -> Self::T {
        (self.0,)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}
