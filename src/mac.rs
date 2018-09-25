//! Implementation of the IEEE 802.15.4 MAC layer


/// PAN ID and short address
pub struct Address {
    /// The PAN ID
    pub pan_id: u16,

    /// 16-bit short address
    pub short_addr: u16,
}
