use crate::{
    magic::{
        hir::{SyscallDef, SyscallId},
        Magic,
    },
    syscall_decode::Decoder,
    Event, EventPayload, RawSyscall, Settings, Syscall,
};
use anyhow::Context;
use nix::{
    sys::{ptrace, wait::WaitStatus},
    unistd::Pid,
};
use std::collections::HashMap;
use tiny_nix_ipc::Socket;

struct ChildInfo {
    in_syscall: bool,
}

fn decode_syscall_args(regs: libc::user_regs_struct) -> RawSyscall {
    let mut out = RawSyscall {
        syscall_id: 0,
        args: [0; 6],
        ret: 0,
    };
    out.ret = regs.rax;
    out.syscall_id = regs.orig_rax;
    out.args[0] = regs.rdi;
    out.args[1] = regs.rsi;
    out.args[2] = regs.rdx;
    out.args[3] = regs.r10;
    out.args[4] = regs.r8;
    out.args[5] = regs.r9;
    out
}

fn process_syscall(
    raw: &RawSyscall,
    proc: Pid,
    magic: &Magic,
    def: &SyscallDef,
) -> Option<Syscall> {
    let mut evaluated = Vec::new();
    evaluated.resize_with(6, Default::default);
    let mut syscall_decoder = Decoder {
        evaluated,
        magic: &magic,
        proc,
        raw,
        syscall: def,
    };

    syscall_decoder.process()
}

fn captute_backtrace(proc: Pid) -> anyhow::Result<crate::backtrace::Backtrace> {
    let mut options = rstack::TraceOptions::new();
    options.ptrace_attach(false);
    options.symbols(true);
    let process_info = options
        .trace(proc.as_raw() as _)
        .context("failed to capture backtrace")?;
    let mut bt = crate::backtrace::Backtrace { threads: vec![] };
    for thread in process_info.threads() {
        let mut thread_info = crate::backtrace::ThreadBacktrace {
            frames: vec![],
            name: None,
            id: thread.id(),
        };
        thread_info.name = thread.name().map(|p| p.to_string());
        let mut frames = Vec::new();
        for frame in thread.frames() {
            let mut frame_info = crate::backtrace::Frame {
                ip: frame.ip() as usize,
                sym: None,
            };
            if let Some(sym) = frame.symbol() {
                frame_info.sym = Some(crate::backtrace::Symbol {
                    addr: sym.address() as usize,
                    name: sym.name().to_string(),
                    offset: sym.offset() as usize,
                    size: sym.size() as usize,
                });
            }

            frames.push(frame_info);
        }
        thread_info.frames = frames;
        bt.threads.push(thread_info);
    }

    Ok(bt)
}

pub(crate) unsafe fn parent(
    mut out: Socket,
    settings: Settings,
    magic: &Magic,
) -> anyhow::Result<()> {
    let pid_children = Pid::from_raw(-1);
    let waitflag = Some(nix::sys::wait::WaitPidFlag::__WALL);
    let mut children: HashMap<u32, ChildInfo> = HashMap::new();
    let mut first_iteration = true;
    while !children.is_empty() || first_iteration {
        first_iteration = false;
        let wstatus =
            nix::sys::wait::waitpid(pid_children, waitflag).context("waitpid() failed")?;
        let pid = wstatus.pid().unwrap().as_raw() as u32; // we don't use WNOHANG
        let child_known = children.contains_key(&pid);
        // None, if child should not be resumed
        // Some(sig_id), if child should be  resumed, and sig_id (if non-null) will be injected
        let mut should_resume = Some(0);
        let event = match (child_known, wstatus) {
            (false, _) => {
                ptrace::setoptions(
                    Pid::from_raw(pid as i32),
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_EXITKILL
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACEEXEC,
                )
                .context("ptrace setoptions failed")?;

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
                should_resume = None;
                Some(ev)
            }
            (true, WaitStatus::PtraceSyscall(_)) => {
                let cur_info = children.get(&pid).unwrap(); // it's guaranteed here that get() returns Some
                let started_syscall = !cur_info.in_syscall;
                let new_info = ChildInfo {
                    in_syscall: started_syscall,
                };
                children.insert(pid, new_info);
                let regs = nix::sys::ptrace::getregs(Pid::from_raw(pid as i32))
                    .context("ptrace getregs failed")?;
                let params = decode_syscall_args(regs);
                let def = magic.lookup_syscall_by_id(SyscallId(params.syscall_id as u32));
                let child_pid = Pid::from_raw(pid as i32);
                let mut decoded_params = match def {
                    Some(def) => process_syscall(&params, child_pid, magic, def),
                    None => None,
                };
                decoded_params.as_mut().map(|p| {
                    // attach backtrace if requested
                    if settings.capture_backtrace {
                        match captute_backtrace(child_pid) {
                            Ok(bt) => p.backtrace = Some(bt),
                            Err(err) => {
                                eprintln!("failed to capture backtrace: {:?}", err);
                            }
                        }
                    }
                });
                if started_syscall {
                    decoded_params.as_mut().map(|p| {
                        // Not provide return value, because it doesn't exist yes
                        p.ret = None;
                    });
                    let ev_payload = EventPayload::Sysenter {
                        raw: params,
                        decoded: decoded_params,
                    };
                    let ev = Event {
                        pid,
                        payload: ev_payload,
                    };
                    match def {
                        Some(def) if def.strategy.on_enter => Some(ev),
                        None => Some(ev),
                        _ => None,
                    }
                } else {
                    let ev_payload = EventPayload::Sysexit {
                        raw: params,
                        decoded: decoded_params,
                    };
                    let ev = Event {
                        pid,
                        payload: ev_payload,
                    };
                    match def {
                        Some(def) if def.strategy.on_exit => Some(ev),
                        None => Some(ev),
                        _ => None,
                    }
                }
            }
            (true, WaitStatus::Stopped(_, sig)) => {
                let payload = EventPayload::Signal {
                    raw: sig as i32,
                    decoded: sig.as_str().to_string(),
                };

                let ev = Event { payload, pid };
                should_resume = Some(sig as i32);
                Some(ev)
            }
            (true, WaitStatus::PtraceEvent(_, _sigtrap, event_id)) => {
                if event_id != libc::PTRACE_EVENT_EXEC {
                    eprintln!("unexpected PtraceEvent: {}", event_id);
                }
                None
            }
            (true, other) => {
                eprintln!("unknown WaitStatus: {:?}", other);
                None
            }
        };
        if let Some(ev) = event {
            out.send_json(&ev, None)
                .map_err(|err| anyhow::anyhow!("{}", err))
                .context("failed to send event")?;
        }
        if let Some(sig) = should_resume {
            let sig = sig as *mut libc::c_void;
            // resume again, if child hasn't finished yet
            // we'd like to use `nix::sys::ptrace::syscall`, but it doesn't support signal injection (https://github.com/nix-rust/nix/pull/1083)
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                std::ptr::null_mut() as *mut libc::c_void,
                sig as *mut libc::c_void,
            );
        }
    }
    let event = Event {
        pid: 0,
        payload: EventPayload::Eos,
    };
    out.send_json(&event, None)
        .map_err(|err| anyhow::anyhow!("{}", err))
        .context("failed to send EOS event")?;

    Ok(())
}
