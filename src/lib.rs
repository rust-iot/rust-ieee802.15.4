//! Partial Rust implementation of the IEEE 802.15.4 standard
//!
//! The [IEEE 802.15.4] standard defines the operation of low-rate wireless
//! personal area networks. This crate aims to be a Rust implementation of this
//! standard.
//!
//! Currently, the main use case for this crate is in the [`dw1000` crate],
//! where it is used to augment the hardware implementation of IEEE 802.15.4 in
//! the [DW1000]. As such, this crate focuses on the parts of IEEE 802.15.4
//! that are required to work with that chip.
//!
//! There are currently no concrete plans to turn this crate into a full
//! implementation of IEEE 802.15.4, but it will be extended as required, as
//! more use cases come up. If you need functionality that this crate doesn't
//! provide yet, please [open an issue] or, better yet, [submit a pull request].
//!
//! [IEEE 802.15.4]: https://en.wikipedia.org/wiki/IEEE_802.15.4
//! [`dw1000` crate]: https://crates.io/crates/dw1000
//! [DW1000]: https://www.decawave.com/product/dw1000-radio-ic/
//! [open an issue]: https://github.com/braun-robotics/rust-ieee802.15.4/issues
//! [submit a pull request]: https://github.com/braun-robotics/rust-ieee802.15.4/pulls


#![deny(missing_docs)]

#![no_std]


pub mod mac;
