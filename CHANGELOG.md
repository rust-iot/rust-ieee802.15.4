### v0.5.0 (2021-03-02)

- Use `byte` crate instead of `bytes` for encoding/decoding ([#35])
- Fix accidental dependence on `alloc` ([#35])
- Fix crate not compiling on thumbv6m targets ([#35])

[#35]: https://github.com/braun-embedded/rust-ieee802.15.4/pull/35


### v0.4.0 (2020-09-15)

- Fix panic when encoding frame header ([#26])
- Add associated constants for broadcast addresses ([#27])
- Replace `&[u8]`/`&mut [u8]` with `&mut dyn Buf`/`&mut dyn BufMut` ([#28])
- Remove `Address::None` in favor of `Option<Address>` ([#28])

[#26]: https://github.com/braun-embedded/rust-ieee802.15.4/pull/26
[#27]: https://github.com/braun-embedded/rust-ieee802.15.4/pull/27
[#28]: https://github.com/braun-embedded/rust-ieee802.15.4/pull/28


### v0.3.0 (2019-04-20)

- Derive more useful traits for the various types ([#20])
- Add support for beacons and MAC commands ([#21])

[#20]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/20
[#21]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/21


### v0.2.0 (2019-03-22)

- Add support for all address modes, including PAN ID compression ([#18])

[#18]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/18


### v0.1.1 (2019-02-20)

- Fix some minor documentation issues


### v0.1.0 (2019-02-04)

Initial release
