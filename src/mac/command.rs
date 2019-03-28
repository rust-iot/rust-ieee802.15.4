//! MAC commands
//!
//! Work in progress

use crate::mac::{DecodeError, PanId, ShortAddress};
use crate::utils::OptionalFrom;

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
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() < 7 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let mut offset = 0;
        let (pan_id, size) = PanId::decode(buf)?;
        offset += size;
        let (coordinator_address, size) = ShortAddress::decode(&buf[offset..])?;
        offset += size;
        let channel = buf[offset];
        offset += 1;
        let (device_address, size) = ShortAddress::decode(&buf[offset..])?;
        offset += size;
        let channel_page = if buf.len() > 7 {
            offset += 1;
            Some(buf[offset - 1])
        } else {
            None
        };
        Ok((
            CoordinatorRealignmentData {
                pan_id,
                coordinator_address,
                channel,
                device_address,
                channel_page,
            },
            offset,
        ))
    }
    /// Encode coordinator re-alignment data into a byte buffer
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer
    ///
    /// # Panics
    ///
    /// Panics if the buffer is not long enough to hold the frame.
    ///
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        let size = self.pan_id.encode(buf);
        offset += size;
        let size = self.coordinator_address.encode(&mut buf[offset..]);
        offset += size;
        buf[offset] = self.channel;
        offset += 1;
        let size = self.device_address.encode(&mut buf[offset..]);
        offset += size;
        if let Some(channel_page) = self.channel_page {
            buf[offset] = channel_page;
            offset += 1;
        }
        offset
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
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buf.len() == 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let cmd = CommandId::optional_from(buf[0]);
        if cmd.is_none() {
            return Err(DecodeError::InvalidValue);
        }
        match cmd.unwrap() {
            CommandId::AssociationRequest => {
                if buf.len() < 2 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let capability = CapabilityInformation::from(buf[1]);
                Ok((Command::AssociationRequest(capability), 2))
            }
            CommandId::AssociationResponse => {
                if buf.len() < 4 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let (address, _) = ShortAddress::decode(&buf[1..])?;
                if let Some(status) = AssociationStatus::optional_from(buf[3]) {
                    Ok((Command::AssociationResponse(address, status), 4))
                } else {
                    return Err(DecodeError::InvalidValue);
                }
            }
            CommandId::DisassociationNotification => {
                if buf.len() < 2 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                if let Some(reason) = DisassociationReason::optional_from(buf[1]) {
                    Ok((Command::DisassociationNotification(reason), 2))
                } else {
                    return Err(DecodeError::InvalidValue);
                }
            }
            CommandId::DataRequest => Ok((Command::DataRequest, 1)),
            CommandId::PanIdConflictNotification => Ok((Command::PanIdConflictNotification, 1)),
            CommandId::OrphanNotification => Ok((Command::OrphanNotification, 1)),
            CommandId::BeaconRequest => Ok((Command::BeaconRequest, 1)),
            CommandId::CoordinatorRealignment => {
                let (data, size) = CoordinatorRealignmentData::decode(&buf[1..])?;
                Ok((Command::CoordinatorRealignment(data), size + 1))
            }
            CommandId::GuaranteedTimeSlotRequest => {
                if buf.len() < 2 {
                    return Err(DecodeError::NotEnoughBytes);
                }
                let characteristics = GuaranteedTimeSlotCharacteristics::from(buf[1]);
                Ok((Command::GuaranteedTimeSlotRequest(characteristics), 2))
            }
        }
    }
    /// Encode the Command into a byte buffer
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer
    ///
    /// # Panics
    ///
    /// Panics if the buffer is not long enough to hold the frame.
    ///
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        match *self {
            Command::AssociationRequest(capability) => {
                buf[0] = u8::from(CommandId::AssociationRequest);
                buf[1] = u8::from(capability);
                2
            }
            Command::AssociationResponse(address, status) => {
                buf[0] = u8::from(CommandId::AssociationResponse);
                let size = address.encode(&mut buf[1..3]);
                buf[size + 1] = u8::from(status);
                size + 2
            }
            Command::DisassociationNotification(reason) => {
                buf[0] = u8::from(CommandId::DisassociationNotification);
                buf[1] = u8::from(reason);
                2
            }
            Command::DataRequest => {
                buf[0] = u8::from(CommandId::DataRequest);
                1
            }
            Command::PanIdConflictNotification => {
                buf[0] = u8::from(CommandId::PanIdConflictNotification);
                1
            }
            Command::OrphanNotification => {
                buf[0] = u8::from(CommandId::OrphanNotification);
                1
            }
            Command::BeaconRequest => {
                buf[0] = u8::from(CommandId::BeaconRequest);
                1
            }
            Command::CoordinatorRealignment(data) => {
                buf[0] = u8::from(CommandId::CoordinatorRealignment);
                let size = data.encode(&mut buf[1..]);
                size + 1
            }
            Command::GuaranteedTimeSlotRequest(characteristics) => {
                buf[0] = u8::from(CommandId::GuaranteedTimeSlotRequest);
                buf[1] = u8::from(characteristics);
                2
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_association_request() {
        let data = [0x01, 0x8e];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
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
        let mut data = [0u8; 32];
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x00]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: true,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x02]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: true,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x04]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: true,
            frame_protection: false,
            allocate_address: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x08]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: true,
            allocate_address: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x40]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: true,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x01, 0x80]);
    }

    #[test]
    fn decode_association_response() {
        let data = [0x02, 0x40, 0x77, 0x00];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 4);
        assert_eq!(
            command,
            Command::AssociationResponse(ShortAddress(0x7740), AssociationStatus::Successful)
        );

        let data = [0x02, 0xaa, 0x55, 0x01];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 4);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x55aa),
                AssociationStatus::NetworkAtCapacity
            )
        );

        let data = [0x02, 0x00, 0x00, 0x02];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 4);
        assert_eq!(
            command,
            Command::AssociationResponse(ShortAddress(0x0000), AssociationStatus::AccessDenied)
        );

        let data = [0x02, 0x00, 0x00, 0x03];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 4);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::HoppingSequenceOffsetDuplication
            )
        );

        let data = [0x02, 0x00, 0x00, 0x80];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 4);
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::FastAssociationSuccesful
            )
        );

        let data = [0x02, 0x00, 0x00, 0x04];
        let result = Command::decode(&data);
        assert!(result.is_err());

        let data = [0x02, 0x00, 0x00, 0x7f];
        let result = Command::decode(&data);
        assert!(result.is_err());

        let data = [0x02, 0x00, 0x00, 0x81];
        let result = Command::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn encode_association_response() {
        let mut data = [0u8; 32];

        let command =
            Command::AssociationResponse(ShortAddress(0x55aa), AssociationStatus::Successful);
        let size = command.encode(&mut data);
        assert_eq!(size, 4);
        assert_eq!(data[..size], [0x02, 0xaa, 0x55, 0x00]);

        let command = Command::AssociationResponse(
            ShortAddress(0x1234),
            AssociationStatus::NetworkAtCapacity,
        );
        let size = command.encode(&mut data);
        assert_eq!(size, 4);
        assert_eq!(data[..size], [0x02, 0x34, 0x12, 0x01]);

        let command =
            Command::AssociationResponse(ShortAddress(0xcffe), AssociationStatus::AccessDenied);
        let size = command.encode(&mut data);
        assert_eq!(size, 4);
        assert_eq!(data[..size], [0x02, 0xfe, 0xcf, 0x02]);

        let command = Command::AssociationResponse(
            ShortAddress(0xfedc),
            AssociationStatus::HoppingSequenceOffsetDuplication,
        );
        let size = command.encode(&mut data);
        assert_eq!(size, 4);
        assert_eq!(data[..size], [0x02, 0xdc, 0xfe, 0x03]);

        let command = Command::AssociationResponse(
            ShortAddress(0x0ff0),
            AssociationStatus::FastAssociationSuccesful,
        );
        let size = command.encode(&mut data);
        assert_eq!(size, 4);
        assert_eq!(data[..size], [0x02, 0xf0, 0x0f, 0x80]);
    }

    #[test]
    fn decode_disassociation_notification() {
        let data = [0x03, 0x01];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
        assert_eq!(
            command,
            Command::DisassociationNotification(DisassociationReason::CoordinatorLeave)
        );

        let data = [0x03, 0x02];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
        assert_eq!(
            command,
            Command::DisassociationNotification(DisassociationReason::DeviceLeave)
        );

        let data = [0x03, 0x00];
        let result = Command::decode(&data);
        assert!(result.is_err());

        let data = [0x03, 0x03];
        let result = Command::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn encode_disassociation_notification() {
        let mut data = [0u8; 32];

        let command = Command::DisassociationNotification(DisassociationReason::CoordinatorLeave);
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x03, 0x01]);

        let command = Command::DisassociationNotification(DisassociationReason::DeviceLeave);
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x03, 0x02]);
    }

    #[test]
    fn decode_coordinator_realignment() {
        let data = [0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 8);
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

        let data = [0x08, 0x34, 0x12, 0x21, 0x43, 0x0b, 0xcd, 0xab, 0x01];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 9);
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
        let mut data = [0u8; 32];

        let command = Command::CoordinatorRealignment(CoordinatorRealignmentData {
            pan_id: PanId(0x1123),
            coordinator_address: ShortAddress(0x0001),
            channel: 15,
            device_address: ShortAddress(0x1234),
            channel_page: None,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 8);
        assert_eq!(
            data[..size],
            [0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12]
        );

        let command = Command::CoordinatorRealignment(CoordinatorRealignmentData {
            pan_id: PanId(0xbeef),
            coordinator_address: ShortAddress(0xfeed),
            channel: 26,
            device_address: ShortAddress(0x1234),
            channel_page: Some(15),
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 9);
        assert_eq!(
            data[..size],
            [0x08, 0xef, 0xbe, 0xed, 0xfe, 0x1a, 0x34, 0x12, 0x0f]
        );
    }

    #[test]
    fn decode_guaranteed_time_slot_request() {
        let data = [0x09, 0x01];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
                count: 1,
                receive_only: false,
                allocation: false,
            })
        );

        let data = [0x09, 0x12];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
                count: 2,
                receive_only: true,
                allocation: false,
            })
        );

        let data = [0x09, 0x23];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 2);
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
        let mut data = [0u8; 32];

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 1,
            receive_only: false,
            allocation: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x09, 0x01]);

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 15,
            receive_only: true,
            allocation: false,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x09, 0x1f]);

        let command = Command::GuaranteedTimeSlotRequest(GuaranteedTimeSlotCharacteristics {
            count: 15,
            receive_only: false,
            allocation: true,
        });
        let size = command.encode(&mut data);
        assert_eq!(size, 2);
        assert_eq!(data[..size], [0x09, 0x2f]);
    }

    #[test]
    fn decode_other_commands() {
        let data = [0x04];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 1);
        assert_eq!(command, Command::DataRequest);

        let data = [0x05];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 1);
        assert_eq!(command, Command::PanIdConflictNotification);

        let data = [0x06];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 1);
        assert_eq!(command, Command::OrphanNotification);

        let data = [0x07];
        let (command, size) = Command::decode(&data).unwrap();
        assert_eq!(size, 1);
        assert_eq!(command, Command::BeaconRequest);
    }

    #[test]
    fn encode_other_commands() {
        let mut data = [0u8; 32];

        let command = Command::DataRequest;
        let size = command.encode(&mut data);
        assert_eq!(size, 1);
        assert_eq!(data[..size], [0x04]);

        let command = Command::PanIdConflictNotification;
        let size = command.encode(&mut data);
        assert_eq!(size, 1);
        assert_eq!(data[..size], [0x05]);

        let command = Command::OrphanNotification;
        let size = command.encode(&mut data);
        assert_eq!(size, 1);
        assert_eq!(data[..size], [0x06]);

        let command = Command::BeaconRequest;
        let size = command.encode(&mut data);
        assert_eq!(size, 1);
        assert_eq!(data[..size], [0x07]);
    }
}
