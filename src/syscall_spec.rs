
pub enum ArgKind {
    /// not used in this syscall
    Null,
    /// handle
    Fd,
    /// pointer to process memory
    User,
    /// number
}
pub struct ArgType {
    kind: ArgKind,
}

#[derive(Serialize, Deserialize)]
pub struct SyscallSpec {
    id: u64,
    args: [ArgType; 6],
}