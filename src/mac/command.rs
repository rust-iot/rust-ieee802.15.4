//! MAC commands
//!
//! Work in progress

use crate::mac::frame::{
    header::{PanId, ShortAddress},
    DecodeError,
};
use crate::utils::OptionalFrom;
use byte::{check_len, BytesExt, TryRead, TryWrite};

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
        let frame_protection =
            byte & CAP_FRAME_PROTECTION == CAP_FRAME_PROTECTION;
        let allocate_address =
            byte & CAP_ALLOCATE_ADDRESS == CAP_ALLOCATE_ADDRESS;
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

impl TryWrite for CoordinatorRealignmentData {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        bytes.write(offset, self.pan_id)?;
        bytes.write(offset, self.coordinator_address)?;
        bytes.write(offset, self.channel)?;
        bytes.write(offset, self.device_address)?;
        if let Some(channel_page) = self.channel_page {
            bytes.write(offset, channel_page)?;
        }
        Ok(*offset)
    }
}

impl TryRead<'_> for CoordinatorRealignmentData {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        check_len(&bytes, 7)?;
        let pan_id = bytes.read(offset)?;
        let coordinator_address = bytes.read(offset)?;
        let channel = bytes.read(offset)?;
        let device_address = bytes.read(offset)?;
        let channel_page = if bytes.len() > *offset {
            Some(bytes.read(offset)?)
        } else {
            None
        };
        Ok((
            Self {
                pan_id,
                coordinator_address,
                channel,
                device_address,
                channel_page,
            },
            *offset,
        ))
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

impl TryWrite for Command {
    fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
        let offset = &mut 0;
        match self {
            Command::AssociationRequest(capability) => {
                bytes.write(offset, u8::from(CommandId::AssociationRequest))?;
                bytes.write(offset, u8::from(capability))?;
            }
            Command::AssociationResponse(address, status) => {
                bytes
                    .write(offset, u8::from(CommandId::AssociationResponse))?;
                bytes.write(offset, address)?;
                bytes.write(offset, u8::from(status))?;
            }
            Command::DisassociationNotification(reason) => {
                bytes.write(
                    offset,
                    u8::from(CommandId::DisassociationNotification),
                )?;
                bytes.write(offset, u8::from(reason))?;
            }
            Command::DataRequest => {
                bytes.write(offset, u8::from(CommandId::DataRequest))?;
            }
            Command::PanIdConflictNotification => {
                bytes.write(
                    offset,
                    u8::from(CommandId::PanIdConflictNotification),
                )?;
            }
            Command::OrphanNotification => {
                bytes.write(offset, u8::from(CommandId::OrphanNotification))?;
            }
            Command::BeaconRequest => {
                bytes.write(offset, u8::from(CommandId::BeaconRequest))?;
            }
            Command::CoordinatorRealignment(data) => {
                bytes.write(
                    offset,
                    u8::from(CommandId::CoordinatorRealignment),
                )?;
                bytes.write(offset, data)?;
            }
            Command::GuaranteedTimeSlotRequest(characteristics) => {
                bytes.write(
                    offset,
                    u8::from(CommandId::GuaranteedTimeSlotRequest),
                )?;
                bytes.write(offset, u8::from(characteristics))?;
            }
        }
        Ok(*offset)
    }
}

impl TryRead<'_> for Command {
    fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let cmd = CommandId::optional_from(bytes.read::<u8>(offset)?)
            .ok_or(DecodeError::InvalidValue)?;
        Ok((
            match cmd {
                CommandId::AssociationRequest => {
                    let capability =
                        CapabilityInformation::from(bytes.read::<u8>(offset)?);
                    Command::AssociationRequest(capability)
                }
                CommandId::AssociationResponse => {
                    let address: ShortAddress = bytes.read(offset)?;
                    let status =
                        AssociationStatus::optional_from(bytes.read(offset)?)
                            .ok_or(DecodeError::InvalidValue)?;
                    Command::AssociationResponse(address, status)
                }
                CommandId::DisassociationNotification => {
                    let reason = DisassociationReason::optional_from(
                        bytes.read(offset)?,
                    )
                    .ok_or(DecodeError::InvalidValue)?;
                    Command::DisassociationNotification(reason)
                }
                CommandId::DataRequest => Command::DataRequest,
                CommandId::PanIdConflictNotification => {
                    Command::PanIdConflictNotification
                }
                CommandId::OrphanNotification => Command::OrphanNotification,
                CommandId::BeaconRequest => Command::BeaconRequest,
                CommandId::CoordinatorRealignment => {
                    Command::CoordinatorRealignment(bytes.read(offset)?)
                }
                CommandId::GuaranteedTimeSlotRequest => {
                    let characteristics =
                        GuaranteedTimeSlotCharacteristics::from(
                            bytes.read::<u8>(offset)?,
                        );
                    Command::GuaranteedTimeSlotRequest(characteristics)
                }
            },
            *offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_association_request() {
        let data = [0x01, 0x8e];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
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
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x00]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: true,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x02]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: true,
            idle_receive: false,
            frame_protection: false,
            allocate_address: false,
        });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x04]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: true,
            frame_protection: false,
            allocate_address: false,
        });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x08]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: true,
            allocate_address: false,
        });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x40]);

        let command = Command::AssociationRequest(CapabilityInformation {
            full_function_device: false,
            mains_power: false,
            idle_receive: false,
            frame_protection: false,
            allocate_address: true,
        });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x01, 0x80]);
    }

    #[test]
    fn decode_association_response() {
        let data = [0x02, 0x40, 0x77, 0x00];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x7740),
                AssociationStatus::Successful
            )
        );

        let data = [0x02, 0xaa, 0x55, 0x01];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x55aa),
                AssociationStatus::NetworkAtCapacity
            )
        );

        let data = [0x02, 0x00, 0x00, 0x02];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::AccessDenied
            )
        );

        let data = [0x02, 0x00, 0x00, 0x03];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::HoppingSequenceOffsetDuplication
            )
        );

        let data = [0x02, 0x00, 0x00, 0x80];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::AssociationResponse(
                ShortAddress(0x0000),
                AssociationStatus::FastAssociationSuccesful
            )
        );

        let data = [0x02, 0x00, 0x00, 0x04];
        let result = data.read::<Command>(&mut len);
        assert!(result.is_err());

        let data = [0x02, 0x00, 0x00, 0x7f];
        let result = data.read::<Command>(&mut len);
        assert!(result.is_err());

        let data = [0x02, 0x00, 0x00, 0x81];
        let result = data.read::<Command>(&mut len);
        assert!(result.is_err());
    }

    #[test]
    fn encode_association_response() {
        let mut data = [0u8; 4];
        let command = Command::AssociationResponse(
            ShortAddress(0x55aa),
            AssociationStatus::Successful,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, data.len());
        assert_eq!(data[..len], [0x02, 0xaa, 0x55, 0x00]);

        let command = Command::AssociationResponse(
            ShortAddress(0x1234),
            AssociationStatus::NetworkAtCapacity,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, data.len());
        assert_eq!(data[..len], [0x02, 0x34, 0x12, 0x01]);

        let command = Command::AssociationResponse(
            ShortAddress(0xcffe),
            AssociationStatus::AccessDenied,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, data.len());
        assert_eq!(data[..len], [0x02, 0xfe, 0xcf, 0x02]);

        let command = Command::AssociationResponse(
            ShortAddress(0xfedc),
            AssociationStatus::HoppingSequenceOffsetDuplication,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, data.len());
        assert_eq!(data[..len], [0x02, 0xdc, 0xfe, 0x03]);

        let command = Command::AssociationResponse(
            ShortAddress(0x0ff0),
            AssociationStatus::FastAssociationSuccesful,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, data.len());
        assert_eq!(data[..len], [0x02, 0xf0, 0x0f, 0x80]);
    }

    #[test]
    fn decode_disassociation_notification() {
        let data = [0x03, 0x01];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::DisassociationNotification(
                DisassociationReason::CoordinatorLeave
            )
        );

        let data = [0x03, 0x02];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::DisassociationNotification(
                DisassociationReason::DeviceLeave
            )
        );

        let data = [0x03, 0x00];
        let result = data.read::<Command>(&mut len);
        assert!(result.is_err());

        let data = [0x03, 0x03];
        let result = data.read::<Command>(&mut len);
        assert!(result.is_err());
    }

    #[test]
    fn encode_disassociation_notification() {
        let mut data = [0u8; 32];

        let command = Command::DisassociationNotification(
            DisassociationReason::CoordinatorLeave,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x03, 0x01]);

        let command = Command::DisassociationNotification(
            DisassociationReason::DeviceLeave,
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x03, 0x02]);
    }

    #[test]
    fn decode_coordinator_realignment() {
        let data = [0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
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
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
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

        let command =
            Command::CoordinatorRealignment(CoordinatorRealignmentData {
                pan_id: PanId(0x1123),
                coordinator_address: ShortAddress(0x0001),
                channel: 15,
                device_address: ShortAddress(0x1234),
                channel_page: None,
            });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 8);
        assert_eq!(
            &data[..len],
            [0x08, 0x23, 0x11, 0x01, 0x00, 0x0f, 0x34, 0x12]
        );

        let command =
            Command::CoordinatorRealignment(CoordinatorRealignmentData {
                pan_id: PanId(0xbeef),
                coordinator_address: ShortAddress(0xfeed),
                channel: 26,
                device_address: ShortAddress(0x1234),
                channel_page: Some(15),
            });
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 9);
        assert_eq!(
            &data[..len],
            [0x08, 0xef, 0xbe, 0xed, 0xfe, 0x1a, 0x34, 0x12, 0x0f]
        );
    }

    #[test]
    fn decode_guaranteed_time_slot_request() {
        let data = [0x09, 0x01];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(
                GuaranteedTimeSlotCharacteristics {
                    count: 1,
                    receive_only: false,
                    allocation: false,
                }
            )
        );

        let data = [0x09, 0x12];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(
                GuaranteedTimeSlotCharacteristics {
                    count: 2,
                    receive_only: true,
                    allocation: false,
                }
            )
        );

        let data = [0x09, 0x23];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(
            command,
            Command::GuaranteedTimeSlotRequest(
                GuaranteedTimeSlotCharacteristics {
                    count: 3,
                    receive_only: false,
                    allocation: true,
                }
            )
        );
    }

    #[test]
    fn encode_guaranteed_time_slot_request() {
        let mut data = [0u8; 32];

        let command = Command::GuaranteedTimeSlotRequest(
            GuaranteedTimeSlotCharacteristics {
                count: 1,
                receive_only: false,
                allocation: false,
            },
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);

        assert_eq!(data[..len], [0x09, 0x01]);

        let command = Command::GuaranteedTimeSlotRequest(
            GuaranteedTimeSlotCharacteristics {
                count: 15,
                receive_only: true,
                allocation: false,
            },
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x09, 0x1f]);

        let command = Command::GuaranteedTimeSlotRequest(
            GuaranteedTimeSlotCharacteristics {
                count: 15,
                receive_only: false,
                allocation: true,
            },
        );
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 2);
        assert_eq!(data[..len], [0x09, 0x2f]);
    }

    #[test]
    fn decode_other_commands() {
        let data = [0x04];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(command, Command::DataRequest);

        let data = [0x05];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(command, Command::PanIdConflictNotification);

        let data = [0x06];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(command, Command::OrphanNotification);

        let data = [0x07];
        let mut len = 0usize;
        let command: Command = data.read(&mut len).unwrap();
        assert_eq!(len, data.len());
        assert_eq!(command, Command::BeaconRequest);
    }

    #[test]
    fn encode_other_commands() {
        let mut data = [0u8; 32];

        let command = Command::DataRequest;
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 1);
        assert_eq!(data[..len], [0x04]);

        let command = Command::PanIdConflictNotification;
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 1);
        assert_eq!(data[..len], [0x05]);

        let command = Command::OrphanNotification;
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 1);
        assert_eq!(data[..len], [0x06]);

        let command = Command::BeaconRequest;
        let mut len = 0usize;
        data.write(&mut len, command).unwrap();

        assert_eq!(len, 1);
        assert_eq!(data[..len], [0x07]);
    }
}
