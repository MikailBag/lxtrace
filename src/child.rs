use nix::sys::ptrace;
use std::ffi::CString;

pub struct SpawnOptions<'a> {
    pub exe: &'a CString,
    // should contain exe as first argument
    pub argv: &'a [CString],
    pub env: &'a [CString],
}
pub enum Payload<'a> {
    Fn(Box<dyn FnOnce() + Send>),
    Cmd(SpawnOptions<'a>),
}

fn payload_cmd(spawn_opts: SpawnOptions) -> ! {
    if let Err(e) = nix::unistd::execve(spawn_opts.exe, spawn_opts.argv, spawn_opts.env) {
        let err_msg = e.to_string();
        nix::unistd::write(1, err_msg.as_bytes()).ok();
        unsafe {
            libc::exit(libc::EXIT_FAILURE);
        }
    }
    // safety: Ok is never returned, because it contains Void value
    unsafe { std::hint::unreachable_unchecked() }
}

pub(crate) unsafe fn execute_child_payload(action: Payload) -> ! {
    ptrace::traceme().expect("ptrace(TRACEME) failed");
    if libc::raise(libc::SIGSTOP) == -1 {
        panic!("raise(SIGSTOP)")
    }
    match action {
        Payload::Fn(bfn) => {
            bfn();
        }
        Payload::Cmd(spawn_opts) => payload_cmd(spawn_opts),
    }
    libc::exit(0)
}
