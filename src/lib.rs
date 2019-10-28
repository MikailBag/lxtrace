pub mod backtrace;
mod child;
pub mod magic;
mod syscall_decode;
mod tracer;

use anyhow::{anyhow, Context};
pub use child::{Payload, SpawnOptions};
pub use magic::ty::Value;
use magic::Magic;
use serde::{Deserialize, Serialize};
use std::{mem, os::unix::io::RawFd};
use tiny_nix_ipc::Socket;

pub struct Settings {
    pub capture_backtrace: bool,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawSyscall {
    pub syscall_id: u64,
    pub args: [u64; 6],
    pub ret: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Syscall {
    pub name: String,
    pub args: Vec<Value>,
    // sysenter: Some
    // sysexit: None
    pub ret: Option<Value>,
    // only provided on sysenter events, if backtrace capture was requested
    pub backtrace: Option<backtrace::Backtrace>,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
#[serde(rename_all = "kebab-case")]
pub enum EventPayload {
    Attach,
    Sysenter {
        /// First field - raw syscall args as is in registers
        raw: RawSyscall,
        /// Second field - parsed data
        decoded: Option<Syscall>,
    },
    Sysexit {
        raw: RawSyscall,
        decoded: Option<Syscall>,
    },
    Signal {
        raw: i32,
        decoded: String,
    },
    Exit(i32),
    /// Internal
    /// for this event pid=0
    /// tracer is about to exit because all tracees have finished
    Eos,
    #[doc(hidden)]
    __NonExhaustive,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub payload: EventPayload,
    pub pid: u32,
}

unsafe fn split(payload: Payload, settings: Settings, out: Socket, magic: &Magic) -> ! {
    let res = libc::fork();
    if res == -1 {
        libc::exit(1);
    }
    if res != 0 {
        tracer::parent(out, settings, magic).ok();
    } else {
        mem::forget(out);
        child::execute_child_payload(payload);
    }
    libc::exit(0);
}

pub unsafe fn run(
    payload: Payload,
    settings: Settings,
    out: crossbeam::channel::Sender<Event>,
) -> anyhow::Result<()> {
    let (mut rcv, snd) = tiny_nix_ipc::Socket::new_socketpair()
        .map_err(|err| anyhow!("{}", err))
        .context("failed to create socket pair")?;

    let magic = magic_init();

    let res = libc::fork();
    if res == -1 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()).context("fork failed"));
    }

    if res != 0 {
        mem::forget(snd);
        loop {
            let msg = rcv
                .recv_json::<Event, [RawFd; 0]>(16384)
                .map_err(|err| anyhow!("{}", err))
                .context("failed to receive event")?
                .0;
            match msg.payload {
                EventPayload::Eos => {
                    break Ok(());
                }
                _ => {
                    out.send(msg)
                        .map_err(|err| anyhow!("{}", err))
                        .context("failed to send event")?;
                }
            }
        }
    } else {
        mem::forget(rcv);
        split(payload, settings, snd, &magic)
    }
}

static MAGIC: &str = include_str!("../magic.ktrace");

pub fn magic_init() -> magic::Magic {
    magic::init(MAGIC)
}
