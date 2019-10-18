use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum PrimitiveTy {
    /// handle
    Fd,
    /// number
    Number,
    /// zero-terminated string
    ZString,
    /// Buffer
    Buffer,
    /// Signal ID
    Signal,
    /// Address
    Address,
}

/// Data type
#[derive(Debug, Clone)]
pub enum Ty {
    /// not used in this syscall
    Null,
    Primitive(PrimitiveTy),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
#[serde(rename_all = "kebab-case")]
// TODO: #[non_exhaustive]
pub enum Value {
    Integral(i64),
    Handle(u32 /*raw fd value*/, Option<u64> /* ray id*/),
    String(String),
    Buffer(Box<[u8]>),
    Flags(u64, Vec<String>),
    Signal(i32, Option<String>),
    Address(u64),
    Error(i32, String),
    Unknown,
    #[doc(hidden)]
    __NonExhaustive,
}

impl Value {
    pub fn is_known(&self) -> bool {
        match self {
            Value::Unknown => false,
            _ => true,
        }
    }

    pub fn is_scalar(&self) -> bool {
        true // revisit when implement structs
    }

    pub fn project<'a>(
        &'a self,
        mut path: impl Iterator<Item = impl AsRef<str>>,
    ) -> Option<&'a Value> {
        match self {
            smth if smth.is_scalar() => {
                if path.next().is_none() {
                    Some(self)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
