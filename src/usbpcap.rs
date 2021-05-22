use crate::{types::*, Packet};

/// Represents a USB PCAP packet ([Link Type 249](https://www.tcpdump.org/linktypes.html)).
#[derive(Packet)]
pub struct UsbPcap {
    pub header_length: u16le,
    pub irp_id: u64le,
    pub status: u32le,
    pub function: u16le,
    pub reserved_info: u7,
    pub pdo_to_fdo: u1,
    pub bus: u16le,
    pub device: u16le,
    pub direction: u1,
    pub reserved_endpoint: u3,
    pub endpoint: u4,
    pub transfer: u8,
    pub data_length: u32le,
    #[length = "header_length - 27"]
    pub header_payload: Vec<u8>,
    #[length = "data_length"]
    #[payload]
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    // use pnet_macros_support::packet::Packet;

    #[test]
    fn usbpcap_packet_test() {
        let mut packet = [0u8; 35];
        {
            let mut usbpcap = MutableUsbPcapPacket::new(&mut packet[..]).unwrap();
            usbpcap.set_header_length(27);
            assert_eq!(usbpcap.get_header_length(), 27);

            usbpcap.set_irp_id(0x12_34);
            assert_eq!(usbpcap.get_irp_id(), 0x12_34);

            usbpcap.set_status(30);
            assert_eq!(usbpcap.get_status(), 30);

            usbpcap.set_function(40);
            assert_eq!(usbpcap.get_function(), 40);

            assert_eq!(usbpcap.get_reserved_info(), 0);

            usbpcap.set_pdo_to_fdo(1);
            assert_eq!(usbpcap.get_pdo_to_fdo(), 1);

            usbpcap.set_bus(60);
            assert_eq!(usbpcap.get_bus(), 60);

            usbpcap.set_device(70);
            assert_eq!(usbpcap.get_device(), 70);

            usbpcap.set_direction(1);
            assert_eq!(usbpcap.get_direction(), 1);

            assert_eq!(usbpcap.get_reserved_endpoint(), 0);

            usbpcap.set_endpoint(14);
            assert_eq!(usbpcap.get_endpoint(), 14);

            usbpcap.set_transfer(80);
            assert_eq!(usbpcap.get_transfer(), 80);

            usbpcap.set_data_length(2);
            assert_eq!(usbpcap.get_data_length(), 2);

            assert_eq!(usbpcap.get_header_payload(), &[]);

            usbpcap.set_payload(&[90, 100]);
            assert_eq!(usbpcap.payload(), &[90, 100]);
        }

        let ref_packet = [
            27, 0, // Header length
            0x34, 0x12, 0, 0, 0, 0, 0, 0, // IRP ID
            30, 0, 0, 0, // Status
            40, 0, // Function
            1, // Info octet
            60, 0, // Bus
            70, 0,   // Device
            142, // Endpoint fields
            80,  // Transfer field
            2, 0, 0, 0, // Data length field
            // No header payload
            90, 100, // Payload
        ];

        assert_eq!(&ref_packet[..], &packet[0..29]);
    }

    #[test]
    fn usbpcap_packet_test_variable_header() {
        let mut packet = [0u8; 35];
        {
            let mut usbpcap = MutableUsbPcapPacket::new(&mut packet[..]).unwrap();
            usbpcap.set_header_length(28);
            assert_eq!(usbpcap.get_header_length(), 28);

            usbpcap.set_header_payload(&[110]);
            assert_eq!(usbpcap.get_header_payload(), &[110]);

            assert_eq!(usbpcap.payload(), &[]);
        }

        let ref_packet = [
            28, 0, // Header length
            0, 0, 0, 0, 0, 0, 0, 0, // IRP ID
            0, 0, 0, 0, // Status
            0, 0, // Function
            0, // Info
            0, 0, // Bus
            0, 0, // Device
            0, // Endpoint fields
            0, // Transfer field
            0, 0, 0, 0, // Data length field
            110, // Header payload
               // No payload
        ];

        assert_eq!(&ref_packet[..], &packet[0..28]);
    }
}
