pub mod magic;
mod syscall_decode;
mod tracer;

use crate::syscall_decode::Decoder;
use nix::sys::ptrace;
use serde::{Deserialize, Serialize};
use std::{mem, os::unix::io::RawFd};
use tiny_nix_ipc::Socket;

pub struct SpawnOptions {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub enum Payload {
    Fn(Box<dyn FnOnce() + Send>),
    Cmd(SpawnOptions),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DecodedArg {
    Num(i128),
    Handle(u32 /*raw fd value*/, Option<u64> /* ray id*/),
    String(String),
    Flags(u64, Vec<String>),
    Unknown,
}

impl Default for DecodedArg {
    fn default() -> DecodedArg {
        DecodedArg::Unknown
    }
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawSyscall {
    pub syscall_id: u64,
    pub args: [u64; 6],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Syscall {
    pub name: String,
    pub args_decoded: Vec<DecodedArg>,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub enum EventPayload {
    Attach,
    /// First field - raw syscall args as is in registers
    /// Second field - parsed data
    Sysenter(RawSyscall, Option<Syscall>),
    Exit(i32),
    /// Internal
    /// for this event pid=0
    /// tracer is about to exit because all tracees have finished
    Eos,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub payload: EventPayload,
    pub pid: u32,
}

unsafe fn child(action: Payload) -> ! {
    ptrace::traceme().expect("ptrace(TRACEME) failed");
    if libc::raise(libc::SIGSTOP) == -1 {
        panic!("raise(SIGSTOP)")
    }
    match action {
        Payload::Fn(bfn) => {
            bfn();
        }
        Payload::Cmd(spawn_opts) => {
            std::process::Command::new(&spawn_opts.argv[0])
                .args(&spawn_opts.argv[1..])
                .envs(spawn_opts.env.iter().map(|&(ref k, ref v)| (k, v)))
                .spawn()
                .unwrap()
                .wait()
                .unwrap();
        }
    }
    libc::exit(0)
}

type Res = Result<(), ()>;

trait ResultExt {
    type Ok;
    fn conv(self) -> Result<Self::Ok, ()>;
}

impl<T, E> ResultExt for Result<T, E> {
    type Ok = T;
    fn conv(self) -> Result<T, ()> {
        self.map_err(|_err| ())
    }
}

unsafe fn split(payload: Payload, out: Socket, decoder: Decoder) -> ! {
    let res = libc::fork();
    if res == -1 {
        libc::exit(1);
    }
    if res != 0 {
        tracer::parent(out, decoder).ok();
    } else {
        mem::forget(out);
        child(payload);
    }
    libc::exit(0);
}

pub unsafe fn run(payload: Payload, out: crossbeam::channel::Sender<Event>) -> Res {
    let (mut rcv, snd) = tiny_nix_ipc::Socket::new_socketpair().conv()?;

    let magic = magic_init();
    let syscall_decoder = syscall_decode::Decoder::new(&magic);

    let res = libc::fork();
    if res == -1 {
        return Err(());
    }

    if res != 0 {
        mem::forget(snd);
        loop {
            let msg = rcv.recv_json::<Event, [RawFd; 0]>(4096).conv()?.0;
            match msg.payload {
                EventPayload::Eos => {
                    break Ok(());
                }
                _ => {
                    out.send(msg).conv()?;
                }
            }
        }
    } else {
        mem::forget(rcv);
        split(payload, snd, syscall_decoder)
    }
}

static MAGIC: &str = include_str!("../magic.ktrace");

pub fn magic_init() -> magic::Magic {
    magic::init(MAGIC)
}
