use nix::{
    sys::{ptrace, wait::WaitStatus},
    unistd::Pid,
};
use std::{collections::HashMap, mem, os::unix::io::RawFd};
use tiny_nix_ipc::Socket;

pub struct SpawnOptions {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub enum Payload {
    Fn(Box<dyn FnOnce() + Send>),
    Cmd(SpawnOptions),
}

#[derive(Debug)]
pub enum DecodedArg {
    NumSigned(u64),
    NumUnsigned(i64),
    Handle(u32, u64),
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
#[derive(Default, Debug)]
pub struct Syscall {
    count: u8,
    syscall_id: u64,
    args: [u64; 6],
    args_decoded: [DecodedArg; 6],
}

#[repr(C)]
#[derive(Debug)]
pub enum EventPayload {
    Attach,
    Sysenter(Syscall),
    Exit(i32),
    /// for this event pid=0
    /// tracer is about to exit because all tracees have finished
    Eos,
}

#[repr(C)]
#[derive(Debug)]
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

fn decode_syscall_args(regs: libc::user_regs_struct) -> Syscall {
    let mut out = Syscall::default();
    out.syscall_id = regs.orig_rax;
    out.args[0] = regs.rdi;
    out.args[1] = regs.rsi;
    out.args[2] = regs.rdx;
    out.args[3] = regs.r10;
    out.args[4] = regs.r8;
    out.args[5] = regs.r9;
    out
}

struct ChildInfo {
    in_syscall: bool,
}

unsafe fn parent(mut out: Socket) -> Res {
    let pid_children = Pid::from_raw(-1);
    let waitflag = Some(nix::sys::wait::WaitPidFlag::__WALL);
    let mut num_children = 1; //at start, we have one tracee, started by run()
    let mut children: HashMap<u32, ChildInfo> = HashMap::new();
    while num_children != 0 {
        let wstatus = nix::sys::wait::waitpid(pid_children, waitflag).conv()?;
        let pid = wstatus.pid().unwrap().as_raw() as u32; // we don't use WNOHANG
        let child_known = children.contains_key(&pid);
        let mut should_resume = true;
        let event = match (child_known, wstatus) {
            (false, _) => {
                ptrace::setoptions(
                    Pid::from_raw(pid as i32),
                    ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
                )
                .conv()?;

                let new_child_info = ChildInfo { in_syscall: false };
                children.insert(pid, new_child_info);

                let event = Event {
                    pid,
                    payload: EventPayload::Attach,
                };

                Some(event)
            }
            (true, WaitStatus::Exited(_, exit_code)) => {
                let ev_payload = EventPayload::Exit(exit_code);
                let ev = Event {
                    payload: ev_payload,
                    pid,
                };
                children.remove(&pid);
                num_children -= 1;
                should_resume = false;
                Some(ev)
            }
            (true, WaitStatus::PtraceSyscall(_)) => {
                let cur_info = children.get(&pid).unwrap().clone(); // it's guaranteed here that get() returns Some
                let started_syscall = !cur_info.in_syscall;
                let new_info = ChildInfo {
                    in_syscall: started_syscall,
                };
                children.insert(pid, new_info);

                if started_syscall {
                    let regs = nix::sys::ptrace::getregs(Pid::from_raw(pid as i32)).conv()?;
                    let params = decode_syscall_args(regs);
                    let ev_payload = EventPayload::Sysenter(params);
                    let ev = Event {
                        pid,
                        payload: ev_payload,
                    };
                    Some(ev)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(ev) = event {
            out.send_struct(&ev, None).conv()?;
        }
        if should_resume {
            // resume again, if child hasn't finished yet
            ptrace::syscall(Pid::from_raw(pid as i32)).conv()?;
        }
    }
    let event = Event {
        pid: 0,
        payload: EventPayload::Eos,
    };
    out.send_struct(&event, None).conv()?;

    Ok(())
}

unsafe fn split(payload: Payload, out: Socket) -> ! {
    let res = libc::fork();
    if res == -1 {
        libc::exit(1);
    }
    if res != 0 {
        parent(out).ok();
    } else {
        mem::forget(out);
        child(payload);
    }
    libc::exit(0);
}

pub unsafe fn run(payload: Payload, out: crossbeam::channel::Sender<Event>) -> Res {
    let (mut rcv, snd) = tiny_nix_ipc::Socket::new_socketpair().conv()?;
    let res = libc::fork();
    if res == -1 {
        return Err(());
    }
    if res != 0 {
        mem::forget(snd);
        loop {
            let msg = rcv.recv_struct::<Event, [RawFd; 0]>().conv()?.0;
            if let EventPayload::Eos = msg.payload {
                break Ok(());
            }
            out.send(msg).conv()?;
        }
    } else {
        mem::forget(rcv);
        split(payload, snd)
    }
}
