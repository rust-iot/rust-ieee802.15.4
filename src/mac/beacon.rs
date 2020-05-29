//! Beacon
//!
//! Work in progress

use core::convert::From;
use core::mem;

use crate::mac::{DecodeError, ExtendedAddress, ShortAddress};

use bytes::{Buf, BufMut};

/// Beacon order is used to calculate the beacon interval
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BeaconOrder {
    /// Used to calculate at which interval beacons are sent
    ///
    /// Beacon interval  = BaseSuperframeDuration × (2 ^ BeaconOrder)
    BeaconOrder(u8),
    /// Beacon are only sent on demand
    OnDemand,
}

impl From<u8> for BeaconOrder {
    /// Convert u8 to beacon order
    fn from(value: u8) -> Self {
        match value {
            0..=14 => BeaconOrder::BeaconOrder(value),
            _ => BeaconOrder::OnDemand,
        }
    }
}

impl From<BeaconOrder> for u8 {
    /// Convert beacon order to u8
    fn from(value: BeaconOrder) -> Self {
        match value {
            BeaconOrder::BeaconOrder(v) => v,
            BeaconOrder::OnDemand => 15,
        }
    }
}

/// Superframe order, amount of time during wich this superframe is active
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SuperframeOrder {
    /// Ammount of time that the superframe is active
    ///
    /// superframe duration = base superframe duration × (2 ^ superframe order)
    SuperframeOrder(u8),
    /// No superframes are sent
    Inactive,
}

impl From<u8> for SuperframeOrder {
    /// Convert u8 to superframe order
    fn from(value: u8) -> Self {
        match value {
            0..=14 => SuperframeOrder::SuperframeOrder(value),
            _ => SuperframeOrder::Inactive,
        }
    }
}

impl From<SuperframeOrder> for u8 {
    /// Convert superframe order to u8
    fn from(value: SuperframeOrder) -> Self {
        match value {
            SuperframeOrder::SuperframeOrder(v) => v,
            SuperframeOrder::Inactive => 15,
        }
    }
}

/// Superframe specification
///
/// The superframe specification describes the organisation of frames in the
/// air when using superframes and/or periodical beacons.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SuperframeSpecification {
    /// Beacon order, 0-15, where 15 is on demand.
    ///
    /// Beacon interval  = BaseSuperframeDuration × (2 ^ BeaconOrder)
    pub beacon_order: BeaconOrder,
    /// Superframe order, amount of time during wich this superframe is active
    pub superframe_order: SuperframeOrder,
    /// final contention access period slot used
    pub final_cap_slot: u8,
    /// Limit receiving of beacons for a period. Not used if beacon_order is OnDemand.
    pub battery_life_extension: bool,
    /// Frame sent by a coordinator
    pub pan_coordinator: bool,
    /// The coordinator acceppts associations to the PAN
    pub association_permit: bool,
}

const BATTERY_LIFE_EXTENSION: u8 = 0b0001_0000;
const PAN_COORDINATOR: u8 = 0b0100_0000;
const ASSOCIATION_PERMIT: u8 = 0b1000_0000;

impl SuperframeSpecification {
    /// Decode superframe specification from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`SuperframeSpecification`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't are enough or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`SuperframeSpecification`]: struct.SuperframeSpecification.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        const DATA_SIZE: usize = 2;
        if buf.remaining() < DATA_SIZE {
            return Err(DecodeError::NotEnoughBytes);
        }
        let byte = buf.get_u8();
        let beacon_order = BeaconOrder::from(byte & 0x0f);
        let superframe_order = SuperframeOrder::from((byte >> 4) & 0x0f);
        let byte = buf.get_u8();
        let final_cap_slot = byte & 0x0f;
        let battery_life_extension = (byte & BATTERY_LIFE_EXTENSION) == BATTERY_LIFE_EXTENSION;
        let pan_coordinator = (byte & PAN_COORDINATOR) == PAN_COORDINATOR;
        let association_permit = (byte & ASSOCIATION_PERMIT) == ASSOCIATION_PERMIT;
        Ok(Self {
            beacon_order,
            superframe_order,
            final_cap_slot,
            battery_life_extension,
            pan_coordinator,
            association_permit,
        })
    }

    /// Encode superframe specification into a byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        let bo = u8::from(self.beacon_order.clone());
        let so = u8::from(self.superframe_order.clone());
        buf.put_u8((bo & 0x0f) | (so << 4));
        let ble = if self.battery_life_extension {
            BATTERY_LIFE_EXTENSION
        } else {
            0
        };
        let pc = if self.pan_coordinator {
            PAN_COORDINATOR
        } else {
            0
        };
        let ap = if self.association_permit {
            ASSOCIATION_PERMIT
        } else {
            0
        };
        buf.put_u8(self.final_cap_slot & 0x0f | ble | pc | ap);
    }
}

/// Direction of data
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Direction {
    /// Receive data
    Receive,
    /// Transmit data
    Transmit,
}

/// Descriptor of the guaranteed time slots (GTSs)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GuaranteedTimeSlotDescriptor {
    /// Device short address used by this slot
    short_address: ShortAddress,
    /// Slot start
    starting_slot: u8,
    /// Slot length
    length: u8,
    /// Direction of the slot, either transmit or receive
    direction: Direction,
}

impl GuaranteedTimeSlotDescriptor {
    /// Create a new empty slot
    pub fn new() -> Self {
        GuaranteedTimeSlotDescriptor {
            short_address: ShortAddress::broadcast(),
            starting_slot: 0,
            length: 0,
            direction: Direction::Receive,
        }
    }
    /// Decode guaranteed time slot descriptor from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`GuaranteedTimeSlotDescriptor`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't are enough or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`GuaranteedTimeSlotDescriptor`]: struct.GuaranteedTimeSlotDescriptor.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        const DATA_SIZE: usize = 3;
        if buf.remaining() < DATA_SIZE {
            return Err(DecodeError::NotEnoughBytes);
        }
        let short_address = ShortAddress::decode(buf)?;
        let byte = buf.get_u8();
        let starting_slot = byte & 0x0f;
        let length = byte >> 4;
        Ok(Self {
            short_address,
            starting_slot,
            length,
            // This should be updated by the super
            direction: Direction::Receive,
        })
    }

    /// Encode guaranteed time slot descriptor into byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        self.short_address.encode(buf);
        buf.put_u8(self.starting_slot | self.length << 4);
    }
}

impl GuaranteedTimeSlotDescriptor {
    /// Set the direction for this slot
    fn set_direction(&mut self, direction: Direction) {
        self.direction = direction;
    }
    /// Returns `true` if this is a transmit slot
    fn direction_transmit(&self) -> bool {
        self.direction == Direction::Transmit
    }
}

const COUNT_MASK: u8 = 0b0000_0111;
const PERMIT: u8 = 0b1000_0000;

/// Information of the guaranteed time slots (GTSs)
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GuaranteedTimeSlotInformation {
    /// Permit GTS
    pub permit: bool,
    slot_count: usize,
    slots: [GuaranteedTimeSlotDescriptor; 7],
}

impl GuaranteedTimeSlotInformation {
    /// Create a new empty GTS information
    pub fn new() -> Self {
        GuaranteedTimeSlotInformation {
            permit: false,
            slot_count: 0,
            slots: [GuaranteedTimeSlotDescriptor::new(); 7],
        }
    }
    /// Decode guaranteed time slot information from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`GuaranteedTimeSlotInformation`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't are enough or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`GuaranteedTimeSlotInformation`]: struct.GuaranteedTimeSlotInformation.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 1 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let byte = buf.get_u8();
        let slot_count = (byte & COUNT_MASK) as usize;
        let permit = (byte & PERMIT) == PERMIT;
        let mut slots = [GuaranteedTimeSlotDescriptor {
            short_address: ShortAddress::broadcast(),
            starting_slot: 0,
            length: 0,
            direction: Direction::Receive,
        }; 7];
        let mut offset = 1;
        if slot_count > 0 {
            if buf.remaining() < 2 + (3 * slot_count) {
                return Err(DecodeError::NotEnoughBytes);
            }
            let mut direction_mask = buf.get_u8();
            for n in 0..slot_count {
                let mut slot = GuaranteedTimeSlotDescriptor::decode(buf)?;
                let direction = if direction_mask & 0b1 == 0b1 {
                    Direction::Transmit
                } else {
                    Direction::Receive
                };
                slot.set_direction(direction);
                direction_mask = direction_mask >> 1;
                slots[n] = slot;
            }
        }
        Ok(Self {
            permit,
            slot_count,
            slots,
        })
    }
    /// Encode guaranteed time slot information into a byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        assert!(self.slot_count <= 7);
        let permit = if self.permit { PERMIT } else { 0 };

        let header = ((self.slot_count as u8) & COUNT_MASK) | permit;
        buf.put_u8(header);

        if self.slot_count > 0 {
            let direction_mask = {
                let mut dir = 0x01;
                let mut direction_mask = 0u8;
                for n in 0..self.slot_count {
                    let slot = self.slots[n];
                    if slot.direction_transmit() {
                        direction_mask = direction_mask | dir;
                    }
                    dir = dir << 1;
                }
                direction_mask
            };

            buf.put_u8(direction_mask);

            for n in 0..self.slot_count {
                let slot = self.slots[n];
                slot.encode(buf);
            }
        }
    }

    /// Get the slots as a slice
    pub fn slots(&self) -> &[GuaranteedTimeSlotDescriptor] {
        &self.slots[..self.slot_count]
    }
}

const SHORT_MASK: u8 = 0b0000_0111;
const EXTENDED_MASK: u8 = 0b0111_0000;

/// # Pending Address(es)
///
/// Addresses to devices that has pending messages with the coordinator
///
/// ```notrust
/// +--------+-----------------+--------------------+
/// | Header | Short Addresses | Extended Addresses |
/// +--------+-----------------+--------------------+
///     1          0 - 14             0 - 448          octets
/// ```
///
/// ## Header
///
/// ```notrust
/// +-------------+----------+----------------+----------+
/// | Short Count | Reserved | Extended Count | Reserved |
/// +-------------+----------+----------------+----------+
///      0 - 2         3         4 - 6             7        bit
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingAddress {
    short_address_count: usize,
    short_addresses: [ShortAddress; 7],
    extended_address_count: usize,
    extended_addresses: [ExtendedAddress; 7],
}

impl PendingAddress {
    /// Create a new empty PendingAddress struct
    pub fn new() -> Self {
        PendingAddress {
            short_address_count: 0,
            short_addresses: [ShortAddress::broadcast(); 7],
            extended_address_count: 0,
            extended_addresses: [ExtendedAddress::broadcast(); 7],
        }
    }
    /// Decode pending address from byte buffer
    ///
    /// # Returns
    ///
    /// Returns [`PendingAddress`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if the bytes either don't are enough or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`PendingAddress`]: struct.PendingAddress.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 1 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ss = mem::size_of::<ShortAddress>();
        let es = mem::size_of::<ExtendedAddress>();
        let byte = buf.get_u8();
        let sl = (byte & SHORT_MASK) as usize;
        let el = ((byte & EXTENDED_MASK) >> 4) as usize;
        if buf.remaining() < (sl * ss) + (el * es) {
            return Err(DecodeError::NotEnoughBytes);
        }
        let mut short_addresses = [ShortAddress::broadcast(); 7];
        for n in 0..sl {
            let addr = ShortAddress::decode(buf)?;
            short_addresses[n] = addr;
        }
        let mut extended_addresses = [ExtendedAddress::broadcast(); 7];
        for n in 0..el {
            let addr = ExtendedAddress::decode(buf)?;
            extended_addresses[n] = addr;
        }
        Ok(Self {
            short_address_count: sl,
            short_addresses,
            extended_address_count: el,
            extended_addresses,
        })
    }
    /// Encode pending address into byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        assert!(self.short_address_count <= 7);
        assert!(self.extended_address_count <= 7);

        let sl = self.short_address_count;
        let el = self.extended_address_count;

        let it_s_magic = (((el as u8) << 4) & EXTENDED_MASK) | ((sl as u8) & SHORT_MASK); //FIXME give variable meaningful name
        buf.put_u8(it_s_magic);

        for n in 0..self.short_address_count {
            let addr = self.short_addresses[n];
            addr.encode(buf);
        }

        for n in 0..self.extended_address_count {
            let addr = self.extended_addresses[n];
            addr.encode(buf);
        }
    }
    /// Get the short addresses
    pub fn short_addresses(&self) -> &[ShortAddress] {
        &self.short_addresses[..self.short_address_count]
    }
    /// Get the extended address
    pub fn extended_addresses(&self) -> &[ExtendedAddress] {
        &self.extended_addresses[..self.extended_address_count]
    }
}
/// Beacon frame
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Beacon {
    /// Superframe specification
    pub superframe_spec: SuperframeSpecification,
    /// Guaranteed time slot information
    pub guaranteed_time_slot_info: GuaranteedTimeSlotInformation,
    /// Pending addresses
    pub pending_address: PendingAddress,
}

impl Beacon {
    /// Decode beacon frame from byte  buffer
    ///
    /// # Returns
    ///
    /// Returns [`Beacon`] and the number of bytes used are returned
    ///
    /// # Errors
    ///
    /// This function returns an error, if there aren't enough bytes or
    /// dont't contain valid data. Please refer to [`DecodeError`] for details.
    ///
    /// [`DecodeError`]: ../enum.DecodeError.html
    /// [`Beacon`]: struct.Beacon.html
    pub fn decode(buf: &mut dyn Buf) -> Result<Self, DecodeError> {
        let superframe_spec = SuperframeSpecification::decode(buf)?;
        let guaranteed_time_slot_info = GuaranteedTimeSlotInformation::decode(buf)?;
        let pending_address = PendingAddress::decode(buf)?;
        Ok(Self {
            superframe_spec,
            guaranteed_time_slot_info,
            pending_address,
        })
    }

    /// Encode beacon frame into byte buffer
    pub fn encode(&self, buf: &mut dyn BufMut) {
        self.superframe_spec.encode(buf);
        self.guaranteed_time_slot_info.encode(buf);
        self.pending_address.encode(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_superframe_specification() {
        let mut data = &[0xff, 0x0f][..];
        let ss = SuperframeSpecification::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);

        assert_eq!(ss.beacon_order, BeaconOrder::OnDemand);
        assert_eq!(ss.superframe_order, SuperframeOrder::Inactive);
        assert_eq!(ss.final_cap_slot, 0xf);
        assert_eq!(ss.battery_life_extension, false);
        assert_eq!(ss.pan_coordinator, false);
        assert_eq!(ss.association_permit, false);
    }

    #[test]
    fn decode_gts_information() {
        let mut data = &[0x00][..];
        let gts = GuaranteedTimeSlotInformation::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(gts.permit, false);
        assert_eq!(gts.slots().len(), 0);
    }

    #[test]
    fn decode_pending_address() {
        let mut data = &[0x00][..];
        let pa = PendingAddress::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);
        assert_eq!(pa.short_addresses().len(), 0);
        assert_eq!(pa.extended_addresses().len(), 0);
    }

    #[test]
    fn decode_beacon() {
        let mut data = &[0xff, 0x0f, 0x00, 0x00][..];
        let beacon = Beacon::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);

        assert_eq!(beacon.superframe_spec.beacon_order, BeaconOrder::OnDemand);
        assert_eq!(
            beacon.superframe_spec.superframe_order,
            SuperframeOrder::Inactive
        );
        assert_eq!(beacon.superframe_spec.final_cap_slot, 0xf);
        assert_eq!(beacon.superframe_spec.battery_life_extension, false);
        assert_eq!(beacon.superframe_spec.pan_coordinator, false);
        assert_eq!(beacon.superframe_spec.association_permit, false);

        assert_eq!(beacon.guaranteed_time_slot_info.permit, false);
        assert_eq!(beacon.guaranteed_time_slot_info.slots().len(), 0);

        assert_eq!(beacon.pending_address.short_addresses().len(), 0);
        assert_eq!(beacon.pending_address.extended_addresses().len(), 0);

        let mut data = &[
            0x12, 0xc3, 0x82, 0x01, 0x34, 0x12, 0x11, 0x78, 0x56, 0x14, 0x00,
        ][..];
        let beacon = Beacon::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);

        assert_eq!(
            beacon.superframe_spec.beacon_order,
            BeaconOrder::BeaconOrder(2)
        );
        assert_eq!(
            beacon.superframe_spec.superframe_order,
            SuperframeOrder::SuperframeOrder(1)
        );
        assert_eq!(beacon.superframe_spec.final_cap_slot, 3);
        assert_eq!(beacon.superframe_spec.battery_life_extension, false);
        assert_eq!(beacon.superframe_spec.pan_coordinator, true);
        assert_eq!(beacon.superframe_spec.association_permit, true);

        assert_eq!(beacon.guaranteed_time_slot_info.permit, true);
        let slots = beacon.guaranteed_time_slot_info.slots();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].short_address, ShortAddress(0x1234));
        assert_eq!(slots[0].starting_slot, 1);
        assert_eq!(slots[0].length, 1);
        assert_eq!(slots[0].direction, Direction::Transmit);
        assert_eq!(slots[1].short_address, ShortAddress(0x5678));
        assert_eq!(slots[1].starting_slot, 4);
        assert_eq!(slots[1].length, 1);
        assert_eq!(slots[1].direction, Direction::Receive);

        assert_eq!(beacon.pending_address.short_addresses().len(), 0);
        assert_eq!(beacon.pending_address.extended_addresses().len(), 0);

        let mut data = &[
            0x12, 0xc3, 0x82, 0x02, 0x34, 0x12, 0x11, 0x78, 0x56, 0x14, 0x12, 0x34, 0x12, 0x78,
            0x56, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        ][..];
        let beacon = Beacon::decode(&mut data).unwrap();
        assert_eq!(data.remaining(), 0);

        assert_eq!(
            beacon.superframe_spec.beacon_order,
            BeaconOrder::BeaconOrder(2)
        );
        assert_eq!(
            beacon.superframe_spec.superframe_order,
            SuperframeOrder::SuperframeOrder(1)
        );
        assert_eq!(beacon.superframe_spec.final_cap_slot, 3);
        assert_eq!(beacon.superframe_spec.battery_life_extension, false);
        assert_eq!(beacon.superframe_spec.pan_coordinator, true);
        assert_eq!(beacon.superframe_spec.association_permit, true);

        assert_eq!(beacon.guaranteed_time_slot_info.permit, true);
        let slots = beacon.guaranteed_time_slot_info.slots();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].short_address, ShortAddress(0x1234));
        assert_eq!(slots[0].starting_slot, 1);
        assert_eq!(slots[0].length, 1);
        assert_eq!(slots[0].direction, Direction::Receive);
        assert_eq!(slots[1].short_address, ShortAddress(0x5678));
        assert_eq!(slots[1].starting_slot, 4);
        assert_eq!(slots[1].length, 1);
        assert_eq!(slots[1].direction, Direction::Transmit);

        assert_eq!(beacon.pending_address.short_addresses().len(), 2);
        assert_eq!(
            beacon.pending_address.short_addresses()[0],
            ShortAddress(0x1234)
        );
        assert_eq!(
            beacon.pending_address.short_addresses()[1],
            ShortAddress(0x5678)
        );
        assert_eq!(beacon.pending_address.extended_addresses().len(), 1);
        assert_eq!(
            beacon.pending_address.extended_addresses()[0],
            ExtendedAddress(0x0123456789abcdef)
        );
    }

    #[test]
    fn encode_beacon() {
        let superframe_spec = SuperframeSpecification {
            beacon_order: BeaconOrder::OnDemand,
            superframe_order: SuperframeOrder::Inactive,
            final_cap_slot: 0,
            battery_life_extension: false,
            pan_coordinator: true,
            association_permit: true,
        };

        let mut slots = [GuaranteedTimeSlotDescriptor::new(); 7];
        slots[0] = GuaranteedTimeSlotDescriptor {
            short_address: ShortAddress(0x1234),
            starting_slot: 1,
            length: 1,
            direction: Direction::Transmit,
        };

        let guaranteed_time_slot_info = GuaranteedTimeSlotInformation {
            permit: true,
            slot_count: 1,
            slots,
        };

        let mut short_addresses = [ShortAddress::broadcast(); 7];
        short_addresses[0] = ShortAddress(0x7856);
        let mut extended_addresses = [ExtendedAddress::broadcast(); 7];
        extended_addresses[0] = ExtendedAddress(0xaec24a1c2116e260);

        let pending_address = PendingAddress {
            short_address_count: 1,
            short_addresses,
            extended_address_count: 1,
            extended_addresses,
        };

        let beacon = Beacon {
            superframe_spec,
            guaranteed_time_slot_info,
            pending_address,
        };

        const BUFFER_SIZE: usize = 128;
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut sliced_buffer = &mut buffer[..];
        beacon.encode(&mut sliced_buffer);
        let size = BUFFER_SIZE - sliced_buffer.len();
        assert_eq!(size, 18);
        assert_eq!(
            buffer[..size],
            [
                0xff, 0xc0, 0x81, 0x01, 0x34, 0x12, 0x11, 0x11, 0x56, 0x78, 0x60, 0xe2, 0x16, 0x21,
                0x1c, 0x4a, 0xc2, 0xae
            ]
        );
    }
}
