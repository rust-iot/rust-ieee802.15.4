/// A trait for converting a value from one type to another.
/// Any failure in converting will return None.
pub trait OptionalFrom<T: Sized>
where
    Self: Sized,
{
    fn optional_from(value: T) -> Option<Self>;
}

/// Creates an enum with various traits.
/// The first key-value pair is the default used if any conversion would fail.
#[macro_export]
macro_rules! extended_enum {
    ($(#[$outer:meta])* $name:ident, $ty:ty, $($(#[$inner:meta])* $var:ident => $val:expr),+ $(,)*) => (

        $(#[$outer])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub enum $name {
            $(
                $(#[$inner])*
                $var,
            )*
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    $( $val => $name::$var,)*
                    _ => panic!("Invalid value"),
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $( $name::$var => $val, )*
                }
            }
        }

        impl OptionalFrom<$ty> for $name {
            fn optional_from(v: $ty) -> Option<Self> {
                match v {
                    $( $val => Some($name::$var),)*
                    _ => None,
                }
            }
        }

        impl PartialEq<$name> for $ty {
            fn eq(&self, other: &$name) -> bool {
                match *other {
                    $( $name::$var => *self == $val, )*
                }
            }

            fn ne(&self, other: &$name) -> bool {
                match *other {
                    $( $name::$var => *self != $val, )*
                }
            }
        }
    );
}
