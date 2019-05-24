use nix::sys::ptrace;
use std::mem;
pub struct SpawnOptions {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
}

pub enum Payload {
    Fn(Box<dyn FnOnce() + Send>),
    Cmd(SpawnOptions),
}



#[repr(C)]
#[derive(Default, Debug)]
pub struct Syscall {
    
    count: u8,
    syscall_id: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
}

#[repr(C)]
#[derive(Debug)]
pub enum EventPayload {
    Sysenter(Syscall),
    Exit(i32),
}

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub payload: EventPayload,
}

pub type EventChannel = crossbeam::channel::Sender<Event>;

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
    out.arg1 = regs.rdi;
    out.arg2 = regs.rsi;
    out.arg3 = regs.rdx;
    out.arg4 = regs.r10;
    out.arg5 = regs.r8;
    out.arg6 = regs.r9;
    out
}

unsafe fn parent(ch_pid: nix::unistd::Pid, out: EventChannel) -> Res {
    let waitflag = Some(nix::sys::wait::WaitPidFlag::__WALL);
    let wstatus = nix::sys::wait::waitpid(ch_pid, waitflag).conv()?;
    match wstatus {
        nix::sys::wait::WaitStatus::Stopped(_, _) => (),
        _ => return Err(()),
    }

    ptrace::setoptions(
        ch_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .conv()?;
    // resume child

    ptrace::syscall(ch_pid).conv()?;
    let mut in_syscall = false;
    loop {
        let wstatus = nix::sys::wait::waitpid(ch_pid, waitflag).conv()?;
        let mut is_syscall_stop = false;
        if let nix::sys::wait::WaitStatus::Exited(_, exit_code) = wstatus {
            let ev_payload = EventPayload::Exit(exit_code);
            let ev = Event {
                payload: ev_payload,
            };
            out.send(ev).conv()?;
            break;
        }
        if let nix::sys::wait::WaitStatus::PtraceSyscall(_) = wstatus {
            is_syscall_stop = true;
        }
        let is_syscall_stop = is_syscall_stop;
        if !is_syscall_stop {
            continue;
        }
        if in_syscall {
            in_syscall = false;
        } else {
            in_syscall = true;
            let regs = nix::sys::ptrace::getregs(ch_pid).conv()?;
            let params = decode_syscall_args(regs);
            let ev_payload = EventPayload::Sysenter(params);
            let ev = Event {
                payload: ev_payload,
            };
            out.send(ev).conv()?;
        }

        // resume again
        ptrace::syscall(ch_pid).conv()?;
    }

    Ok(())
}

pub unsafe fn run(payload: Payload, out: EventChannel) -> Result<(), ()> {
    let res = libc::fork();
    if res == -1 {
        return Err(());
    }
    if res == 0 {
        mem::forget(out);
        child(payload);
    } else {
        parent(nix::unistd::Pid::from_raw(res), out)
    }
}
