use crate::{
    magic::{
        hir::{SyscallDef, SyscallId},
        Magic,
    },
    syscall_decode::Decoder,
    Event, EventPayload, RawSyscall, Syscall,
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

pub(crate) unsafe fn parent(mut out: Socket, magic: &Magic) -> anyhow::Result<()> {
    let pid_children = Pid::from_raw(-1);
    let waitflag = Some(nix::sys::wait::WaitPidFlag::__WALL);
    let mut num_children = 1; //at start, we have one tracee, started by run()
    let mut children: HashMap<u32, ChildInfo> = HashMap::new();
    while num_children != 0 {
        let wstatus =
            nix::sys::wait::waitpid(pid_children, waitflag).context("waitpid() failed")?;
        let pid = wstatus.pid().unwrap().as_raw() as u32; // we don't use WNOHANG
        let child_known = children.contains_key(&pid);
        let mut should_resume = true;
        let event = match (child_known, wstatus) {
            (false, _) => {
                ptrace::setoptions(
                    Pid::from_raw(pid as i32),
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_EXITKILL
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEVFORK,
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
                num_children -= 1;
                should_resume = false;
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
                let decoded_params = match def {
                    Some(def) => process_syscall(&params, Pid::from_raw(pid as i32), magic, def),
                    None => None,
                };

                if started_syscall {
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
                    decoded: crate::syscall_decode::get_signal_name(sig).to_string(),
                };

                let ev = Event { payload, pid };
                Some(ev)
            }
            _ => None,
        };
        if let Some(ev) = event {
            out.send_json(&ev, None)
                .map_err(|err| anyhow::anyhow!("{}", err))
                .context("failed to send event")?;
        }
        if should_resume {
            // resume again, if child hasn't finished yet
            ptrace::syscall(Pid::from_raw(pid as i32)).context("failed to resume")?;
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
