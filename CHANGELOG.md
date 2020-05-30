<a name="v0.3.0"></a>

### Unreleased
#### Changed
- `&mut [u8]` was changed to `&mut dyn BufMut` in `encode(..)` functions. This allow end-user have control of allocation.
- `&[u8]` was changed whenever possible to `&mut dyn Buf`
- `Address::None` was removed in favour of `Option<Address>`

### v0.3.0 (2019-04-20)

- Derive more useful traits for the various types ([#20])
- Add support for beacons and MAC commands ([#21])

[#20]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/20
[#21]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/21


<a name="v0.2.0"></a>
### v0.2.0 (2019-03-22)

- Add support for all address modes, including PAN ID compression ([#18])

[#18]: https://github.com/braun-robotics/rust-ieee802.15.4/pull/18


<a name="v0.1.1"></a>
### v0.1.1 (2019-02-20)

- Fix some minor documentation issues


<a name="v0.1.0"></a>
### v0.1.0 (2019-02-04)

Initial release
