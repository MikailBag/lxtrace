use crate::{syscall_decode::Decoder, Event, EventPayload, RawSyscall, Res, ResultExt};
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
    };
    out.syscall_id = regs.orig_rax;
    out.args[0] = regs.rdi;
    out.args[1] = regs.rsi;
    out.args[2] = regs.rdx;
    out.args[3] = regs.r10;
    out.args[4] = regs.r8;
    out.args[5] = regs.r9;
    out
}

pub(crate) unsafe fn parent(mut out: Socket, mut decoder: Decoder) -> Res {
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
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_EXITKILL
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEVFORK,
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
                let cur_info = children.get(&pid).unwrap(); // it's guaranteed here that get() returns Some
                let started_syscall = !cur_info.in_syscall;
                let new_info = ChildInfo {
                    in_syscall: started_syscall,
                };
                children.insert(pid, new_info);

                if started_syscall {
                    let regs = nix::sys::ptrace::getregs(Pid::from_raw(pid as i32)).conv()?;
                    let params = decode_syscall_args(regs);
                    let decoded_params = decoder.process(&params, Pid::from_raw(pid as i32));
                    let ev_payload = EventPayload::Sysenter(params, decoded_params);
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
            out.send_json(&ev, None).conv()?;
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
    out.send_json(&event, None).conv()?;

    Ok(())
}
