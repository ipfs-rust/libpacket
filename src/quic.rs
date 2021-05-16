use crate::{types::*, Packet, PrimitiveValues};

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
    pub fn new(mut packet: &'a [u8]) -> Option<Vec<Self>> {
        let mut packets = vec![];
        while !packet.is_empty() {
            if packet.len() < 5 {
                return None;
            }
            let header_form = packet[0] & (1 << 7) > 0;
            let fixed_bit = packet[0] & (1 << 6) > 0;
            let quic = if fixed_bit && !header_form {
                Self::OneRtt(OneRttPacket::new(packet)?)
            } else {
                if packet[1..5] == [0u8; 4] {
                    Self::VersionNegotiation(VersionNegotiationPacket::new(packet)?)
                } else {
                    match (LongPacketType::new((packet[0] >> 4) & 0b11), fixed_bit) {
                        (LongPacketTypes::Initial, true) => {
                            Self::Initial(InitialPacket::new(packet)?)
                        }
                        (LongPacketTypes::ZeroRtt, true) => {
                            Self::ZeroRtt(ZeroRttPacket::new(packet)?)
                        }
                        (LongPacketTypes::Handshake, true) => {
                            Self::Handshake(HandshakePacket::new(packet)?)
                        }
                        (LongPacketTypes::Retry, true) => Self::Retry(RetryPacket::new(packet)?),
                        _ => return None,
                    }
                }
            };
            // lifetime of payload is 'a so this is safe to do.
            let remaining = unsafe { std::mem::transmute(quic.remaining()) };
            packets.push(quic);
            packet = remaining;
        }
        Some(packets)
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

    pub fn packet_number(&self) -> Option<u64> {
        match self {
            Self::VersionNegotiation(_) => None,
            Self::Initial(packet) => Some(packet.get_packet_number_raw()),
            Self::ZeroRtt(packet) => Some(packet.get_packet_number_raw()),
            Self::Handshake(packet) => Some(packet.get_packet_number_raw()),
            Self::Retry(_) => None,
            Self::OneRtt(packet) => Some(packet.get_packet_number_raw()),
        }
        .map(packet_number)
    }

    pub fn dest_id(&self) -> Vec<u8> {
        match self {
            Self::VersionNegotiation(packet) => packet.get_dest_id(),
            Self::Initial(packet) => packet.get_dest_id(),
            Self::ZeroRtt(packet) => packet.get_dest_id(),
            Self::Handshake(packet) => packet.get_dest_id(),
            Self::Retry(packet) => packet.get_dest_id(),
            Self::OneRtt(packet) => packet.get_dest_id(),
        }
    }

    pub fn src_id(&self) -> Option<Vec<u8>> {
        Some(match self {
            Self::VersionNegotiation(packet) => packet.get_src_id(),
            Self::Initial(packet) => packet.get_src_id(),
            Self::ZeroRtt(packet) => packet.get_src_id(),
            Self::Handshake(packet) => packet.get_src_id(),
            Self::Retry(packet) => packet.get_src_id(),
            Self::OneRtt(_) => return None,
        })
    }

    pub fn packet(&self) -> &[u8] {
        match self {
            Self::VersionNegotiation(p) => p.packet(),
            Self::Initial(p) => p.packet(),
            Self::ZeroRtt(p) => p.packet(),
            Self::Handshake(p) => p.packet(),
            Self::Retry(p) => p.packet(),
            Self::OneRtt(p) => p.packet(),
        }
    }

    pub fn frames(&self) -> Option<&[u8]> {
        match self {
            Self::VersionNegotiation(_) => None,
            Self::Initial(packet) => Some(packet.get_frames_raw()),
            Self::ZeroRtt(packet) => Some(packet.get_frames_raw()),
            Self::Handshake(packet) => Some(packet.get_frames_raw()),
            Self::Retry(_) => None,
            Self::OneRtt(packet) => Some(packet.payload()),
        }
    }

    pub fn remaining(&self) -> &[u8] {
        match self {
            Self::VersionNegotiation(_) => &[],
            Self::Initial(packet) => packet.get_remaining_raw(),
            Self::ZeroRtt(packet) => packet.get_remaining_raw(),
            Self::Handshake(packet) => packet.get_remaining_raw(),
            Self::Retry(_) => &[],
            Self::OneRtt(_) => &[],
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
        let dest_id = self.dest_id();
        writeln!(f, "dest-id: {:?}", dest_id)?;
        if let Some(src_id) = self.src_id() {
            writeln!(f, "src-id: {:?}", src_id)?;
        }
        if let Some(payload) = self.frames() {
            writeln!(f, "payload: {}", payload.len())?;
        }
        Ok(())
    }
}

pub fn varint_length(first_byte: u8) -> usize {
    let prefix = first_byte >> 6;
    let length = (1 << prefix) - 1;
    length
}

pub fn varint(first_byte: u8, rest: &[u8]) -> usize {
    let mut length = (first_byte & 0x3f) as u64;
    for v in rest {
        length = (length << 8) + *v as u64;
    }
    length as usize
}

pub fn packet_number(bytes: &[u8]) -> u64 {
    let mut pn = [0; 8];
    pn[(8 - bytes.len())..].copy_from_slice(bytes);
    u64::from_be_bytes(pn)
}

#[derive(Debug, Packet)]
pub struct Varint {
    varint_1: u8,
    #[length = "varint_length(varint_1)"]
    varint_2: Vec<u8>,
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
    #[length = "varint_length(token_length_1)"]
    token_length_2: Vec<u8>,
    #[length = "varint(token_length_1, &token_length_2)"]
    token: Vec<u8>,
    length_1: u8,
    #[length = "varint_length(length_1)"]
    length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[length = "varint(length_1, &length_2) - packet_number.len()"]
    frames: Vec<u8>,
    remaining: Vec<u8>,
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
    length_1: u8,
    #[length = "varint_length(length_1)"]
    length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[length = "varint(length_1, &length_2) - packet_number.len()"]
    frames: Vec<u8>,
    remaining: Vec<u8>,
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
    length_1: u8,
    #[length = "varint_length(length_1)"]
    length_2: Vec<u8>,
    #[length = "packet_number_len + 1"]
    packet_number: Vec<u8>,
    #[length = "varint(length_1, &length_2) - packet_number.len()"]
    frames: Vec<u8>,
    remaining: Vec<u8>,
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

#[derive(Debug)]
pub enum Frame<'a> {
    Padding(PaddingPacket<'a>, usize),
    Ping(PingPacket<'a>),
    Ack(AckPacket<'a>),
    ResetStream(ResetStreamPacket<'a>),
    StopSending(StopSendingPacket<'a>),
    Crypto(CryptoPacket<'a>),
    NewToken(NewTokenPacket<'a>),
    Stream(StreamPacket<'a>),
    MaxData(MaxDataPacket<'a>),
    MaxStreamData(MaxStreamDataPacket<'a>),
    MaxStreams(MaxStreamsPacket<'a>),
    DataBlocked(DataBlockedPacket<'a>),
    StreamDataBlocked(StreamDataBlockedPacket<'a>),
    StreamsBlocked(StreamsBlockedPacket<'a>),
    NewConnectionId(NewConnectionIdPacket<'a>),
    RetireConnectionId(RetireConnectionIdPacket<'a>),
    PathChallenge(PathChallengePacket<'a>),
    PathResponse(PathResponsePacket<'a>),
    ConnectionClose(ConnectionClosePacket<'a>),
    HandshakeDone(HandshakeDonePacket<'a>),
}

impl<'a> Frame<'a> {
    pub fn new(mut packet: &'a [u8]) -> Option<Vec<Self>> {
        let mut frames = vec![];
        while packet.len() > 0 {
            let frame = match FrameType(packet[0]) {
                FrameTypes::Padding => Self::Padding(PaddingPacket::new(packet)?, 1),
                FrameTypes::Ping => Self::Ping(PingPacket::new(packet)?),
                FrameTypes::Ack0 | FrameTypes::Ack1 => Self::Ack(AckPacket::new(packet)?),
                FrameTypes::ResetStream => Self::ResetStream(ResetStreamPacket::new(packet)?),
                FrameTypes::StopSending => Self::StopSending(StopSendingPacket::new(packet)?),
                FrameTypes::Crypto => Self::Crypto(CryptoPacket::new(packet)?),
                FrameTypes::NewToken => Self::NewToken(NewTokenPacket::new(packet)?),
                x if (0x8..=0xf).contains(&x.0) => Self::Stream(StreamPacket::new(packet)?),
                FrameTypes::MaxData => Self::MaxData(MaxDataPacket::new(packet)?),
                FrameTypes::MaxStreamData => Self::MaxStreamData(MaxStreamDataPacket::new(packet)?),
                FrameTypes::MaxStreams0 | FrameTypes::MaxStreams1 => {
                    Self::MaxStreams(MaxStreamsPacket::new(packet)?)
                }
                FrameTypes::DataBlocked => Self::DataBlocked(DataBlockedPacket::new(packet)?),
                FrameTypes::StreamDataBlocked => {
                    Self::StreamDataBlocked(StreamDataBlockedPacket::new(packet)?)
                }
                FrameTypes::StreamsBlocked0 | FrameTypes::StreamsBlocked1 => {
                    Self::StreamsBlocked(StreamsBlockedPacket::new(packet)?)
                }
                FrameTypes::NewConnectionId => {
                    Self::NewConnectionId(NewConnectionIdPacket::new(packet)?)
                }
                FrameTypes::RetireConnectionId => {
                    Self::RetireConnectionId(RetireConnectionIdPacket::new(packet)?)
                }
                FrameTypes::PathChallenge => Self::PathChallenge(PathChallengePacket::new(packet)?),
                FrameTypes::PathResponse => Self::PathResponse(PathResponsePacket::new(packet)?),
                FrameTypes::ConnectionClose0 | FrameTypes::ConnectionClose1 => {
                    Self::ConnectionClose(ConnectionClosePacket::new(packet)?)
                }
                FrameTypes::HandshakeDone => Self::HandshakeDone(HandshakeDonePacket::new(packet)?),
                _ => return None,
            };
            println!("{:x?}", frame);
            // lifetime of payload is 'a so this is safe to do.
            packet = unsafe { std::mem::transmute(frame.remaining()) };
            match (frames.last_mut(), frame) {
                (Some(Frame::Padding(_, x)), Frame::Padding(_, y)) => *x += y,
                (_, frame) => frames.push(frame),
            }
        }
        Some(frames)
    }

    fn ty(&self) -> FrameType {
        match self {
            Self::Padding(p, _) => p.get_ty(),
            Self::Ping(p) => p.get_ty(),
            Self::Ack(p) => p.get_ty(),
            Self::ResetStream(p) => p.get_ty(),
            Self::StopSending(p) => p.get_ty(),
            Self::Crypto(p) => p.get_ty(),
            Self::NewToken(p) => p.get_ty(),
            Self::Stream(p) => p.get_ty(),
            Self::MaxData(p) => p.get_ty(),
            Self::MaxStreamData(p) => p.get_ty(),
            Self::MaxStreams(p) => p.get_ty(),
            Self::DataBlocked(p) => p.get_ty(),
            Self::StreamDataBlocked(p) => p.get_ty(),
            Self::StreamsBlocked(p) => p.get_ty(),
            Self::NewConnectionId(p) => p.get_ty(),
            Self::RetireConnectionId(p) => p.get_ty(),
            Self::PathChallenge(p) => p.get_ty(),
            Self::PathResponse(p) => p.get_ty(),
            Self::ConnectionClose(p) => p.get_ty(),
            Self::HandshakeDone(p) => p.get_ty(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Padding(p, _) => p.payload(),
            Self::Ping(p) => p.payload(),
            Self::Ack(p) => p.payload(),
            Self::ResetStream(p) => p.payload(),
            Self::StopSending(p) => p.payload(),
            Self::Crypto(p) => p.payload(),
            Self::NewToken(p) => p.payload(),
            Self::Stream(p) => p.payload(),
            Self::MaxData(p) => p.payload(),
            Self::MaxStreamData(p) => p.payload(),
            Self::MaxStreams(p) => p.payload(),
            Self::DataBlocked(p) => p.payload(),
            Self::StreamDataBlocked(p) => p.payload(),
            Self::StreamsBlocked(p) => p.payload(),
            Self::NewConnectionId(p) => p.payload(),
            Self::RetireConnectionId(p) => p.payload(),
            Self::PathChallenge(p) => p.payload(),
            Self::PathResponse(p) => p.payload(),
            Self::ConnectionClose(p) => p.payload(),
            Self::HandshakeDone(p) => p.payload(),
        }
    }

    fn remaining(&self) -> &[u8] {
        match self {
            Self::Padding(p, _) => p.get_remaining_raw(),
            Self::Ping(p) => p.get_remaining_raw(),
            Self::Ack(p) => p.get_remaining_raw(),
            Self::ResetStream(p) => p.get_remaining_raw(),
            Self::StopSending(p) => p.get_remaining_raw(),
            Self::Crypto(p) => p.get_remaining_raw(),
            Self::NewToken(p) => p.get_remaining_raw(),
            Self::Stream(p) => p.get_remaining_raw(),
            Self::MaxData(p) => p.get_remaining_raw(),
            Self::MaxStreamData(p) => p.get_remaining_raw(),
            Self::MaxStreams(p) => p.get_remaining_raw(),
            Self::DataBlocked(p) => p.get_remaining_raw(),
            Self::StreamDataBlocked(p) => p.get_remaining_raw(),
            Self::StreamsBlocked(p) => p.get_remaining_raw(),
            Self::NewConnectionId(p) => p.get_remaining_raw(),
            Self::RetireConnectionId(p) => p.get_remaining_raw(),
            Self::PathChallenge(p) => p.get_remaining_raw(),
            Self::PathResponse(p) => p.get_remaining_raw(),
            Self::ConnectionClose(p) => p.get_remaining_raw(),
            Self::HandshakeDone(p) => p.get_remaining_raw(),
        }
    }
}

impl<'a> std::fmt::Display for Frame<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ty())
    }
}

#[derive(Debug, Packet)]
pub struct Padding {
    #[construct_with(u8)]
    ty: FrameType,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Ping {
    #[construct_with(u8)]
    ty: FrameType,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Ack {
    #[construct_with(u8)]
    ty: FrameType,
    largest_acknowledged_1: u8,
    #[length = "varint_length(largest_acknowledged_1)"]
    largest_acknowledged_2: Vec<u8>,
    ack_delay_1: u8,
    #[length = "varint_length(ack_delay_1)"]
    ack_delay_2: Vec<u8>,
    ack_range_count_1: u8,
    #[length = "varint_length(ack_range_count_1)"]
    ack_range_count_2: Vec<u8>,
    first_ack_range_1: u8,
    #[length = "varint_length(first_ack_range_1)"]
    first_ack_range_2: Vec<u8>,
    #[length = "varint(ack_range_count_1, &ack_range_count_2)"]
    ack_range: Vec<Varint>,
    #[length = "if ty.0 == 0x03 { 3 } else { 0 }"]
    ecn_counts: Vec<Varint>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct ResetStream {
    #[construct_with(u8)]
    ty: FrameType,
    stream_id_1: u8,
    #[length = "varint_length(stream_id_1)"]
    stream_id_2: Vec<u8>,
    application_protocol_error_code_1: u8,
    #[length = "varint_length(application_protocol_error_code_1)"]
    application_protocol_error_code_2: Vec<u8>,
    final_size_1: u8,
    #[length = "varint_length(final_size_1)"]
    final_size_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct StopSending {
    #[construct_with(u8)]
    ty: FrameType,
    stream_id_1: u8,
    #[length = "varint_length(stream_id_1)"]
    stream_id_2: Vec<u8>,
    application_protocol_error_code_1: u8,
    #[length = "varint_length(application_protocol_error_code_1)"]
    application_protocol_error_code_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Crypto {
    #[construct_with(u8)]
    ty: FrameType,
    offset_1: u8,
    #[length = "varint_length(offset_1)"]
    offset_2: Vec<u8>,
    length_1: u8,
    #[length = "varint_length(length_1)"]
    length_2: Vec<u8>,
    #[length = "varint(length_1, &length_2)"]
    crypto_payload: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct NewToken {
    #[construct_with(u8)]
    ty: FrameType,
    token_length_1: u8,
    #[length = "varint_length(token_length_1)"]
    token_length_2: Vec<u8>,
    #[length = "varint(token_length_1, &token_length_2)"]
    token: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct Stream {
    #[construct_with(u8)]
    ty: FrameType,
    stream_id_1: u8,
    #[length = "varint_length(stream_id_1)"]
    stream_id_2: Vec<u8>,
    #[length = "if ty.0 & 0x04 > 0 { 1 } else { 0 }"]
    offset: Vec<Varint>,
    #[length = "if ty.0 & 0x02 > 0 { 1 } else { 0 }"]
    length: Vec<Varint>,
    #[payload]
    #[length = "if length.is_empty() { 2000 } else { varint(length[0].varint_1, &length[0].varint_2) }"]
    stream_data: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct MaxData {
    #[construct_with(u8)]
    ty: FrameType,
    max_data_1: u8,
    #[length = "varint_length(max_data_1)"]
    max_data_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct MaxStreamData {
    #[construct_with(u8)]
    ty: FrameType,
    stream_id_1: u8,
    #[length = "varint_length(stream_id_1)"]
    stream_id_2: Vec<u8>,
    max_stream_data_1: u8,
    #[length = "varint_length(max_stream_data_1)"]
    max_stream_data_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct MaxStreams {
    #[construct_with(u8)]
    ty: FrameType,
    max_streams_1: u8,
    #[length = "varint_length(max_streams_1)"]
    max_streams_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct DataBlocked {
    #[construct_with(u8)]
    ty: FrameType,
    max_data_1: u8,
    #[length = "varint_length(max_data_1)"]
    max_data_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct StreamDataBlocked {
    #[construct_with(u8)]
    ty: FrameType,
    stream_id_1: u8,
    #[length = "varint_length(stream_id_1)"]
    stream_id_2: Vec<u8>,
    max_stream_data_1: u8,
    #[length = "varint_length(max_stream_data_1)"]
    max_stream_data_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct StreamsBlocked {
    #[construct_with(u8)]
    ty: FrameType,
    max_streams_1: u8,
    #[length = "varint_length(max_streams_1)"]
    max_streams_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct NewConnectionId {
    #[construct_with(u8)]
    ty: FrameType,
    sequence_number_1: u8,
    #[length = "varint_length(sequence_number_1)"]
    sequence_number_2: Vec<u8>,
    retire_prior_to_1: u8,
    #[length = "varint_length(retire_prior_to_1)"]
    retire_prior_to_2: Vec<u8>,
    length: u8,
    #[length = "length"]
    connection_id: Vec<u8>,
    #[length = "16"]
    stateless_reset_token: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct RetireConnectionId {
    #[construct_with(u8)]
    ty: FrameType,
    sequence_number_1: u8,
    #[length = "varint_length(sequence_number_1)"]
    sequence_number_2: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct PathChallenge {
    #[construct_with(u8)]
    ty: FrameType,
    #[length = "8"]
    data: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct PathResponse {
    #[construct_with(u8)]
    ty: FrameType,
    #[length = "8"]
    data: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct ConnectionClose {
    #[construct_with(u8)]
    ty: FrameType,
    error_code_1: u8,
    #[length = "varint_length(error_code_1)"]
    error_code_2: Vec<u8>,
    #[length = "if ty.0 == 0x1d { 0 } else { 1 }"]
    frame_type: Vec<Varint>,
    reason_phrase_length_1: u8,
    #[length = "varint_length(reason_phrase_length_1)"]
    reason_phrase_length_2: Vec<u8>,
    #[length = "varint(reason_phrase_length_1, &reason_phrase_length_2)"]
    reason_phrase: Vec<u8>,
    remaining: Vec<u8>,
}

#[derive(Debug, Packet)]
pub struct HandshakeDone {
    #[construct_with(u8)]
    ty: FrameType,
    remaining: Vec<u8>,
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod FrameTypes {
    use super::FrameType;

    pub const Padding: FrameType = FrameType(0x00);
    pub const Ping: FrameType = FrameType(0x01);
    pub const Ack0: FrameType = FrameType(0x02);
    pub const Ack1: FrameType = FrameType(0x03);
    pub const ResetStream: FrameType = FrameType(0x04);
    pub const StopSending: FrameType = FrameType(0x05);
    pub const Crypto: FrameType = FrameType(0x06);
    pub const NewToken: FrameType = FrameType(0x07);
    pub const Stream0: FrameType = FrameType(0x08);
    pub const Stream1: FrameType = FrameType(0x09);
    pub const Stream2: FrameType = FrameType(0x0a);
    pub const Stream3: FrameType = FrameType(0x0b);
    pub const Stream4: FrameType = FrameType(0x0c);
    pub const Stream5: FrameType = FrameType(0x0d);
    pub const Stream6: FrameType = FrameType(0x0e);
    pub const Stream7: FrameType = FrameType(0x0f);
    pub const MaxData: FrameType = FrameType(0x10);
    pub const MaxStreamData: FrameType = FrameType(0x11);
    pub const MaxStreams0: FrameType = FrameType(0x12);
    pub const MaxStreams1: FrameType = FrameType(0x13);
    pub const DataBlocked: FrameType = FrameType(0x14);
    pub const StreamDataBlocked: FrameType = FrameType(0x15);
    pub const StreamsBlocked0: FrameType = FrameType(0x16);
    pub const StreamsBlocked1: FrameType = FrameType(0x17);
    pub const NewConnectionId: FrameType = FrameType(0x18);
    pub const RetireConnectionId: FrameType = FrameType(0x19);
    pub const PathChallenge: FrameType = FrameType(0x1a);
    pub const PathResponse: FrameType = FrameType(0x1b);
    pub const ConnectionClose0: FrameType = FrameType(0x1c);
    pub const ConnectionClose1: FrameType = FrameType(0x1d);
    pub const HandshakeDone: FrameType = FrameType(0x1e);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameType(pub u8);

impl FrameType {
    /// Construct a new `FrameType`.
    pub fn new(val: u8) -> Self {
        Self(val)
    }
}

impl PrimitiveValues for FrameType {
    type T = (u8,);
    fn to_primitive_values(&self) -> Self::T {
        (self.0,)
    }
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            &FrameTypes::Padding => "padding",
            &FrameTypes::Ping => "ping",
            &FrameTypes::Ack0 | &FrameTypes::Ack1 => "ack",
            &FrameTypes::ResetStream => "reset-stream",
            &FrameTypes::StopSending => "stop-sending",
            &FrameTypes::Crypto => "crypto",
            &FrameTypes::NewToken => "new-token",
            x if (0x8..0xf).contains(&x.0) => "stream",
            &FrameTypes::MaxData => "max-data",
            &FrameTypes::MaxStreamData => "max-stream-data",
            &FrameTypes::MaxStreams0 | &FrameTypes::MaxStreams1 => "max-streams",
            &FrameTypes::DataBlocked => "data-blocked",
            &FrameTypes::StreamDataBlocked => "stream-data-blocked",
            &FrameTypes::StreamsBlocked0 | &FrameTypes::StreamsBlocked1 => "streams-blocked",
            &FrameTypes::NewConnectionId => "new-connection-id",
            &FrameTypes::RetireConnectionId => "retire-connection-id",
            &FrameTypes::PathChallenge => "path-challenge",
            &FrameTypes::PathResponse => "path-response",
            &FrameTypes::ConnectionClose0 | &FrameTypes::ConnectionClose1 => "connection-close",
            &FrameTypes::HandshakeDone => "handshake-done",
            _ => "unknown",
        };
        write!(f, "{}", s)
    }
}
