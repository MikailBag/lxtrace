#[derive(Debug, Clone)]
pub enum PrimitiveTy {
    /// handle
    Fd,
    /// number
    Number,
    /// zero-terminated string
    ZString,
}

/// Data type
#[derive(Debug, Clone)]
pub enum Ty {
    /// not used in this syscall
    Null,
    Primitive(PrimitiveTy),
}
