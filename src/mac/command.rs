//! MAC commands
//!
//! Work in progress

use crate::mac::{DecodeError, PanId, ShortAddress};
use crate::utils::OptionalFrom;

use bytes::{Buf, BufMut};

extended_enum!(
    /// MAC command identifiers
    CommandId, u8,
    /// Association request, request association to PAN
    AssociationRequest => 1,
    /// Association response
    AssociationResponse => 2,
    /// Dissassociation notification
    DisassociationNotification => 3,
    /// Data request
    DataRequest => 4,
    /// PAN identifier conflict notification, sent from coordinator to offending device
    PanIdConflictNotification => 5,
    /// Orphan notification,
    OrphanNotification => 6,
    /// Beacon request, sent from a device which want to join a PAN
    BeaconRequest => 7,
    /// Coordinator re-alignment, the coordinator will change network parameters
    CoordinatorRealignment => 8,
    /// Guaranteed time slot request, request a guaranteed time slot
    GuaranteedTimeSlotRequest => 9,
);

const CAP_FFD: u8 = 0x02;
const CAP_MAINS_POWER: u8 = 0x04;
const CAP_IDLE_RECEIVE: u8 = 0x08;
const CAP_FRAME_PROTECTION: u8 = 0x40;
const CAP_ALLOCATE_ADDRESS: u8 = 0x80;

/// Association request capability information
///
/// Sent with association request to report the capabilities of the device.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityInformation {
    /// Full-function device (FFD) or a reduced-function device (RFD)
    /// RFD and FFD have different function sets.
    pub full_function_device: bool,
    /// Device is connected to a mains power source or not
    pub mains_power: bool,
    /// Receive is enabled while idle
    pub idle_receive: bool,
    /// Frames are cryptographically protected
    pub frame_protection: bool,
    /// Device wish to have an short address allocated by the coordinator
    pub allocate_address: bool,
}

impl From<u8> for CapabilityInformation {
    fn from(byte: u8) -> Self {
        let full_function_device = byte & CAP_FFD == CAP_FFD;
        let mains_power = byte & CAP_MAINS_POWER == CAP_MAINS_POWER;
        let idle_receive = byte & CAP_IDLE_RECEIVE == CAP_IDLE_RECEIVE;
        let frame_protection = byte & CAP_FRAME_PROTECTION == CAP_FRAME_PROTECTION;
        let allocate_address = byte & CAP_ALLOCATE_ADDRESS == CAP_ALLOCATE_ADDRESS;
        Self {
            full_function_device,
            mains_power,
            idle_receive,
            frame_protection,
            allocate_address,
        }
    }
}

impl From<CapabilityInformation> for u8 {
    fn from(ar: CapabilityInformation) -> Self {
        let mut byte = 0u8;
        if ar.full_function_device {
            byte = byte | CAP_FFD;
        }
        if ar.mains_power {
            byte = byte | CAP_MAINS_POWER;
        }
        if ar.idle_receive {
            byte = byte | CAP_IDLE_RECEIVE;
        }
        if ar.frame_protection {
            byte = byte | CAP_FRAME_PROTECTION;
        }
        if ar.allocate_address {
            byte = byte | CAP_ALLOCATE_ADDRESS;
        }
        byte
    }
}

extended_enum!(
    /// Association Status
    AssociationStatus, u8,
    /// Successful
    Successful => 0x00,
    /// Network (PAN) at capacity
    NetworkAtCapacity => 0x01,
    /// Access to PAN denied
    AccessDenied => 0x02,
    /// Duplicate hopping sequence offset
    HoppingSequenceOffsetDuplication => 0x03,
    /// Fast association was successful
    FastAssociationSuccesful => 0x80,
);

extended_enum!(
    /// Disassociation Reason
    DisassociationReason, u8,
    /// Coordinator requested device to leave
    CoordinatorLeave => 1,
    /// Device requested to leave
    DeviceLeave => 2,
);

/// Coordinator re-alignment data
///
/// Changes to the PAN sent by the coordinator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorRealignmentData {
    /// PAN id that the coordinator will use
    pub pan_id: PanId,
    /// Short address that the coordinator will use
    pub coordinator_address: ShortAddress,
    /// Channel that the coordinator will use
    pub channel: u8,
    /// Device address or broadcast
    pub device_address: ShortAddress,
    /// Channel page or channel number the coordinator will use
    pub channel_page: Option<u8>,
}

impl CoordinatorRealignmentData {
    /// Decode coordinator re-alignment data from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`CoordinatorRealignmentData`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if there aren't enough bytes or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`CoordinatorRealignmentData`]: struct.CoordinatorRealignmentData.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 7 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let pan_id = PanId::decode(buf)?;
        let coordinator_address = ShortAddress::decode(buf)?;
        let channel = buf.get_u8();
        let device_address = ShortAddress::decode(buf)?;
        let channel_page = if buf.has_remaining() {
            Some(buf.get_u8())
        } else {
            None
        };
        Ok(Self {
            pan_id,
            coordinator_address,
            channel,
            device_address,
            channel_page,
        })
    }
    /// Encode coordinator re-alignment data into a byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        self.pan_id.encode(buf);
        self.coordinator_address.encode(buf);
        buf.put_u8(self.channel);
        self.device_address.encode(buf);
        if let Some(channel_page) = self.channel_page {
            buf.put_u8(channel_page);
        }
    }
}

const GTSC_RECEIVE_ONLY: u8 = 0x10;
const GTSC_ALLOCATION: u8 = 0x20;

/// Guaranteed time slot characteristics
///
/// GTS configuration requested with the guaranteed time slot request command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GuaranteedTimeSlotCharacteristics {
    /// Number of slots requested
    pub count: u8,
    /// Receive only slots, otherwise transmit
    pub receive_only: bool,
    /// Request type, Allocate or de-allocate
    pub allocation: bool,
}

impl From<u8> for GuaranteedTimeSlotCharacteristics {
    fn from(byte: u8) -> Self {
        let receive_only = byte & GTSC_RECEIVE_ONLY == GTSC_RECEIVE_ONLY;
        let allocation = byte & GTSC_ALLOCATION == GTSC_ALLOCATION;
        Self {
            count: (byte & 0x0f),
            receive_only,
            allocation,
        }
    }
}

impl From<GuaranteedTimeSlotCharacteristics> for u8 {
    fn from(gtsc: GuaranteedTimeSlotCharacteristics) -> Self {
        let mut byte = gtsc.count & 0x0f;
        if gtsc.receive_only {
            byte = byte | GTSC_RECEIVE_ONLY;
        }
        if gtsc.allocation {
            byte = byte | GTSC_ALLOCATION;
        }
        byte
    }
}

/// MAC commands
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Command {
    /// Association request, request association to a PAN
    AssociationRequest(CapabilityInformation),
    /// Association response, response to a association request
    AssociationResponse(ShortAddress, AssociationStatus),
    /// Notification of disassociation from the PAN
    DisassociationNotification(DisassociationReason),
    /// Request for data
    DataRequest,
    /// Notification of PAN idetifier conflict
    PanIdConflictNotification,
    /// Notification of orphan
    OrphanNotification,
    /// Request a beacon
    BeaconRequest,
    /// Coordinator re-alignment, the coordinator will change PAN parameters
    CoordinatorRealignment(CoordinatorRealignmentData),
    /// Request a guaranteed time slot (GTS)
    GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics),
}

impl Command {
    /// Decode MAC command from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`Command`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't are enough or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`Command`]: enum.Command.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() == 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let cmd = CommandId::optional_from(buf.get_u8()).ok_or(DecodeError::InvalidValue)?;
        match cmd {
            CommandId::AssociationRequest => {
                if buf.remaining() < 1 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let capability = CapabilityInformation::from(buf.get_u8());
                Ok(Command::AssociationRequest(capability))
            }
            CommandId::AssociationResponse => {
                if buf.remaining() < 3 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let address = ShortAddress::decode(buf)?;
                let status = AssociationStatus::optional_from(buf.get_u8())
                    .ok_or(DecodeError::InvalidValue)?;
                Ok(Command::AssociationResponse(address, status))
            }
            CommandId::DisassociationNotification => {
                if buf.remaining() < 1 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let reason = DisassociationReason::optional_from(buf.get_u8())
                    .ok_or(DecodeError::InvalidValue)?;
                Ok(Command::DisassociationNotification(reason))
            }
            CommandId::DataRequest => Ok(Command::DataRequest),
            CommandId::PanIdConflictNotification => Ok(Command::PanIdConflictNotification),
            CommandId::OrphanNotification => Ok(Command::OrphanNotification),
            CommandId::BeaconRequest => Ok(Command::BeaconRequest),
            CommandId::CoordinatorRealignment => {
                let data = CoordinatorRealignmentData::decode(buf)?;
                Ok(Command::CoordinatorRealignment(data))
            }
            CommandId::GuaranteedTimeSlotRequest => {
                if buf.remaining() < 1 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let characteristics = GuaranteedTimeSlotCharacteristics::from(buf.get_u8());
                Ok(Command::GuaranteedTimeSlotRequest(characteristics))
            }
        }
    }

    /// Encode the Command into a byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        match *self {
            Command::AssociationRequest(capability) => {
                buf.put_u8(u8::from(CommandId::AssociationRequest));
                buf.put_u8(u8::from(capability));
            }
            Command::AssociationResponse(address, status) => {
                buf.put_u8(u8::from(CommandId::AssociationResponse));
                address.encode(buf);
                buf.put_u8(u8::from(status));
            }
            Command::DisassociationNotification(reason) => {
                buf.put_u8(u8::from(CommandId::DisassociationNotification));
                buf.put_u8(u8::from(reason));
            }
            Command::DataRequest => {
                buf.put_u8(u8::from(CommandId::DataRequest));
            }
            Command::PanIdConflictNotification => {
                buf.put_u8(u8::from(CommandId::PanIdConflictNotification));
            }
            Command::OrphanNotification => {
                buf.put_u8(u8::from(CommandId::OrphanNotification));
            }
            Command::BeaconRequest => {
                buf.put_u8(u8::from(CommandId::BeaconRequest));
            }
            Command::CoordinatorRealignment(data) => {
                buf.put_u8(u8::from(CommandId::CoordinatorRealignment));
                data.encode(buf);
            }
            Command::GuaranteedTimeSlotRequest(characteristics) => {
                buf.put_u8(u8::from(CommandId::GuaranteedTimeSlotRequest));
                buf.put_u8(u8::from(characteristics));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn decode_association_request() {
        let mut data = &[0x01, 0x8e][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationRequest(CapabilityInformation {
                full_function_device: true,
                mains_power: true,
                idle_receive: true,
                frame_protection: false,
                allocate_address: true,
            })
        );
    }

    #[test]
    fn encode_association_request() {
        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        let mut data = BytesMut::with_capacity(32);
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x00]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: true,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x02]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: true,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x04]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: true,
            frame_protection: false,
            allocate_address: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x08]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: true,
            allocate_address: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x40]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: true,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x01, 0x80]);
    }

    #[test]
    fn decode_association_response() {
        let mut data = &[0x02, 0x40, 0x77, 0x00][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationResponse(ShortAddress(0x7740), AssociationStatus::Successful)
        );

        let mut data = &[0x02, 0xaa, 0x55, 0x01][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x55aa),
                AssociationStatus::NetworkAtCapacity
            )
        );

        let mut data = &[0x02, 0x00, 0x00, 0x02][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationResponse(ShortAddress(0x0000), AssociationStatus::AccessDenied)
        );

        let mut data = &[0x02, 0x00, 0x00, 0x03][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::HoppingSequenceOffsetDuplication
            )
        );

        let mut data = &[0x02, 0x00, 0x00, 0x80][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::FastAssociationSuccesful
            )
        );

        let mut data = &[0x02, 0x00, 0x00, 0x04][..];
        let result = Command::decode(&mut data);
        assert!(result.is_err());

        let mut data = &[0x02, 0x00, 0x00, 0x7f][..];
        let result = Command::decode(&mut data);
        assert!(result.is_err());

        let mut data = &[0x02, 0x00, 0x00, 0x81][..];
        let result = Command::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn encode_association_response() {
        let mut data = BytesMut::with_capacity(2); // Don't panic when not enough init data
        let command =
            Command::AssociationResponse(ShortAddress(0x55aa), AssociationStatus::Successful);
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 4);
        assert_eq!(encoded_data[..], [0x02, 0xaa, 0x55, 0x00]);

        let command = Command::AssociationResponse(
            ShortAddress(0x1234),
            AssociationStatus::NetworkAtCapacity,
        );
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 4);
        assert_eq!(encoded_data[..], [0x02, 0x34, 0x12, 0x01]);

        let command =
            Command::AssociationResponse(ShortAddress(0xcffe), AssociationStatus::AccessDenied);
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 4);
        assert_eq!(encoded_data[..], [0x02, 0xfe, 0xcf, 0x02]);

        let command = Command::AssociationResponse(
            ShortAddress(0xfedc),
            AssociationStatus::HoppingSequenceOffsetDuplication,
        );
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 4);
        assert_eq!(encoded_data[..], [0x02, 0xdc, 0xfe, 0x03]);

        let command = Command::AssociationResponse(
            ShortAddress(0x0ff0),
            AssociationStatus::FastAssociationSuccesful,
        );
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 4);
        assert_eq!(encoded_data[..], [0x02, 0xf0, 0x0f, 0x80]);
    }

    #[test]
    fn decode_disassociation_notification() {
        let mut data = &[0x03, 0x01][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::DisassociationNotification(DisassociationReason::CoordinatorLeave)
        );

        let mut data = &[0x03, 0x02][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::DisassociationNotification(DisassociationReason::DeviceLeave)
        );

        let mut data = &[0x03, 0x00][..];
        let result = Command::decode(&mut data);
        assert!(result.is_err());

        let mut data = &[0x03, 0x03][..];
        let result = Command::decode(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn encode_disassociation_notification() {
        let mut data = BytesMut::with_capacity(32);

        let command = Command::DisassociationNotification(DisassociationReason::CoordinatorLeave);
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x03, 0x01]);

        let command = Command::DisassociationNotification(DisassociationReason::DeviceLeave);
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x03, 0x02]);
    }

    #[test]
    fn decode_coordinator_realignment() {
        let mut data = &[0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.len(), 0);
        assert_eq!(
            command,
            Command::CoordinatorRealignment(CoordinatorRealignmentData {
                pan_id: PanId(0x1123),
                coordinator_address: ShortAddress(0x0001),
                channel: 15,
                device_address: ShortAddress(0x1234),
                channel_page: None,
            })
        );

        let mut data = &[0x08, 0x34, 0x12, 0x21, 0x43, 0x0b, 0xcd, 0xab, 0x01][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.len(), 0);
        assert_eq!(
            command,
            Command::CoordinatorRealignment(CoordinatorRealignmentData {
                pan_id: PanId(0x1234),
                coordinator_address: ShortAddress(0x4321),
                channel: 11,
                device_address: ShortAddress(0xabcd),
                channel_page: Some(1),
            })
        );
    }

    #[test]
    fn encode_coordinator_realignment() {
        let mut data = BytesMut::with_capacity(32);

        let command = Command::CoordinatorRealignment(CoordinatorRealignmentData {
            pan_id: PanId(0x1123),
            coordinator_address: ShortAddress(0x0001),
            channel: 15,
            device_address: ShortAddress(0x1234),
            channel_page: None,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 8);
        assert_eq!(
            encoded_data[..],
            [0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12]
        );

        let command = Command::CoordinatorRealignment(CoordinatorRealignmentData {
            pan_id: PanId(0xbeef),
            coordinator_address: ShortAddress(0xfeed),
            channel: 26,
            device_address: ShortAddress(0x1234),
            channel_page: Some(15),
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 9);
        assert_eq!(
            encoded_data[..],
            [0x08, 0xef, 0xbe, 0xed, 0xfe, 0x1a, 0x34, 0x12, 0x0f]
        );
    }

    #[test]
    fn decode_guaranteed_time_slot_request() {
        let mut data = &[0x09, 0x01][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
                count: 1,
                receive_only: false,
                allocation: false,
            })
        );

        let mut data = &[0x09, 0x12][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
                count: 2,
                receive_only: true,
                allocation: false,
            })
        );

        let mut data = &[0x09, 0x23][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
                count: 3,
                receive_only: false,
                allocation: true,
            })
        );
    }

    #[test]
    fn encode_guaranteed_time_slot_request() {
        let mut data = BytesMut::with_capacity(32);

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 1,
            receive_only: false,
            allocation: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);

        assert_eq!(encoded_data[..], [0x09, 0x01]);

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 15,
            receive_only: true,
            allocation: false,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x09, 0x1f]);

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 15,
            receive_only: false,
            allocation: true,
        });
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 2);
        assert_eq!(encoded_data[..], [0x09, 0x2f]);
    }

    #[test]
    fn decode_other_commands() {
        let mut data = &[0x04][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(command, Command::DataRequest);

        let mut data = &[0x05][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(command, Command::PanIdConflictNotification);

        let mut data = &[0x06][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(command, Command::OrphanNotification);

        let mut data = &[0x07][..];
        let command = Command::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(command, Command::BeaconRequest);
    }

    #[test]
    fn encode_other_commands() {
        let mut data = BytesMut::with_capacity(32);

        let command = Command::DataRequest;
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 1);
        assert_eq!(encoded_data[..], [0x04]);

        let command = Command::PanIdConflictNotification;
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 1);
        assert_eq!(encoded_data[..], [0x05]);

        let command = Command::OrphanNotification;
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 1);
        assert_eq!(encoded_data[..], [0x06]);

        let command = Command::BeaconRequest;
        command.encode(&mut data);
        let encoded_data = data.split().freeze();
        assert_eq!(encoded_data.len(), 1);
        assert_eq!(encoded_data[..], [0x07]);
    }
}
