//! This contains MLME-Scan.request, .confirm and .indication
use heapless::Vec;

/// 7.1.11.1 - MLME-SCAN.request
/// is used to initiate a channel scan over a given list of channels.
pub struct MlmeScanRequest {
    /// Indicates the type of scan performed
    pub scan_type: ScanType,
    /// indicate which channels are to be scanne
    pub channels: u32,
    /// value used to calculate the length of time to spend scanning each channel for ED, active, and passive scans.
    pub scan_duration: u8,
}

/// 7.1.11.2 - MLME-SCAN.confirm
/// defines the scan primitive
pub struct MlmeScanConfirm {
    /// The status of the scan request.
    pub status: ScanStatus,
    /// Indicates if the type of scan performed
    pub scan_type: ScanType,
    /// Channels not scanned (bitmask)
    pub unscanned_channels: u32,
    /// Number of results in lists
    pub result_list_size: u8,
    /// list of energy measurements, one for each channel searched during an ED scan.
    pub energy_detect_list: Option<Vec<u8, 255>>,
    /// Beacons found during scan
    pub pan_descriptor_list: Option<Vec<PanDescriptor, 255>>,
}

/// 7.1.11.2.1
pub enum ScanType {
    /// FFD only
    EnergyDetection = 0x00,
    /// FFD only
    Active = 0x01,
    /// passive scan
    Passive = 0x02,
    /// orphan scan
    Orphan = 0x03,
}

/// 7.1.11.1.3
pub enum ScanStatus {
    /// requested scan was successful
    Success,
    /// limit reached
    LimitReached,
    /// primitive is not supported or is out of range
    InvalidParameter,
}

/// Table 41
pub struct PanDescriptor {
    /// The address of the coordinator as specified in the received beacon frame.
    pub coord_addr: u64,
    /// The PAN identifier of the coordinator as specified in the received beacon frame.
    pub coord_pan_id: u16,
    /// The current logical channel occupied by the network.
    pub channel: u8,
    /// The LQ at which the network beacon was received.
    pub link_quality: u8,
}
