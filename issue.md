Supporting security on MAC layer is impossible due to immutability of `Frame::payload`

# The problem
I'm trying to implement the security features specified by the 802.15.4 standard. Implementing the features by themselves and encrypting outgoing frames
is working as expected, but I've run into a roadblock when it comes to decrypting incoming frames. You can find the (unfinished) progress [here](https://gitlab.com/datdenkikniet/rust-ieee802154/-/tree/security_features).

Because `Frame::payload` is immutable, we cannot perform in-place unsecuring of the payload, and because it is a reference, we can't create a copy of the secured data, unsecure it, and reassign the payload. 

Moving the calling responsibility of the unsecuring operation to a higher layer is also very difficult, as `TryRead` constrains the kind of Error we can return. Even if that would be possible, the issue of immutability still prevents that higher layer from performing the unsecuring in-place.

# Possible solutions
