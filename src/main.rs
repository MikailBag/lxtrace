use anyhow::Context;
use lxtrace::{self, Event, EventPayload, Value};
use std::{ffi::CString, io::Write, ops::Deref, path::PathBuf, process::exit};
use structopt::StructOpt;

fn print_data(arg: &Value, wr: &mut dyn Write) -> std::io::Result<()> {
    match arg {
        Value::Integral(num) => write!(wr, "{}", num)?,
        Value::Handle(raw_fd, fd_ray) => {
            write!(wr, "{}", raw_fd)?;
            if let Some(ray) = fd_ray {
                write!(wr, "@{}", ray)?;
            }
        }
        Value::String(s) => {
            write!(wr, "\"{}\"", s)?;
        }
        Value::Buffer(buf) => {
            if let Ok(s) = std::str::from_utf8(&buf) {
                write!(wr, "\"{}\"", s)?;
            } else {
                write!(wr, "<binary data>")?;
            }
        }
        Value::Flags(_, _) => {
            write!(wr, "TODO: flags")?;
        }
        Value::Signal(si_code, si_name) => match si_name {
            Some(name) => write!(wr, "{}", name)?,
            None => write!(wr, "signal #{}", si_code)?,
        },
        Value::Address(addr) => write!(wr, "{:p}", *addr as usize as *const ())?,
        Value::Error(code, name) => write!(wr, "error #{}: {}", code, name)?,
        Value::Unknown => {
            write!(wr, "<unknown>")?;
        }
        Value::__NonExhaustive => unreachable!(),
    }
    Ok(())
}

#[derive(Copy, Clone)]
enum SyscallEvent {
    Enter,
    Exit,
}

fn print_syscall_event(ev: Event, kind: SyscallEvent, wr: &mut dyn Write) -> std::io::Result<()> {
    match ev.payload {
        EventPayload::Sysenter {
            raw: raw_data,
            decoded: data,
        }
        | EventPayload::Sysexit {
            raw: raw_data,
            decoded: data,
        } => {
            match &data {
                Some(data) => {
                    write!(
                        wr,
                        "[{}]: syscall {} {} (",
                        ev.pid,
                        &data.name,
                        match kind {
                            SyscallEvent::Enter => "started",
                            SyscallEvent::Exit => "finished",
                        }
                    )?;
                    for (i, arg) in data.args.iter().enumerate() {
                        if i != 0 {
                            write!(wr, ", ")?; // TODO properly put commas and spacing
                        }
                        print_data(arg, wr)?;
                    }
                    write!(wr, ")")?;
                }
                None => write!(
                    wr,
                    "[{}]: unknown syscall start {}({}, {}, {}, {}, {}, {})",
                    ev.pid,
                    raw_data.syscall_id,
                    raw_data.args[0],
                    raw_data.args[1],
                    raw_data.args[2],
                    raw_data.args[3],
                    raw_data.args[4],
                    raw_data.args[5]
                )?,
            }
            match kind {
                SyscallEvent::Enter => writeln!(wr)?,
                SyscallEvent::Exit => {
                    write!(wr, " = ")?;

                    match &data {
                        Some(dec) if dec.ret.as_ref().unwrap().is_known() => {
                            print_data(dec.ret.as_ref().unwrap(), wr)?;
                            writeln!(wr,)?
                        }
                        _ => writeln!(wr, "{}", raw_data.ret)?,
                    }
                }
            }
            if let Some(data) = &data {
                if let Some(backtrace) = &data.backtrace {
                    for thread in backtrace.threads() {
                        if let Some(name) = thread.name() {
                            writeln!(wr, "thread {} at:", name)?;
                        } else {
                            writeln!(wr, "thread #{} at:", thread.id())?;
                        }
                        for (i, frame) in thread.frames().iter().enumerate() {
                            write!(wr, "\t {}: ", i)?;
                            if let Some(sym) = frame.sym() {
                                writeln!(wr, "`{}`", sym.demangle())?;
                            } else {
                                writeln!(wr, "0x{:016x}", frame.ip())?;
                            }
                        }
                    }
                    writeln!(wr)?;
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn print_event(event: Event, wr: &mut dyn Write) -> std::io::Result<()> {
    match event.payload {
        EventPayload::Attach => {
            writeln!(wr, "[{}]: attached", event.pid)?;
        }
        EventPayload::Exit(exit_code) => {
            writeln!(wr, "[{}]: exited, code={}", event.pid, exit_code)?;
        }
        EventPayload::Sysenter { .. } => print_syscall_event(event, SyscallEvent::Enter, wr)?,
        EventPayload::Sysexit { .. } => print_syscall_event(event, SyscallEvent::Exit, wr)?,
        EventPayload::Signal {
            raw: sig_code,
            decoded: sig_name,
        } => {
            writeln!(
                wr,
                "[{}]: stopped by signal {} (code {})",
                event.pid, sig_name, sig_code
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[derive(Clone)]
struct XCString(CString);

impl std::str::FromStr for XCString {
    type Err = std::ffi::NulError;

    fn from_str(s: &str) -> Result<XCString, Self::Err> {
        CString::new(s).map(XCString)
    }
}

impl std::ops::Deref for XCString {
    type Target = CString;
    fn deref(&self) -> &CString {
        &self.0
    }
}

#[derive(StructOpt, Clone)]
struct Opt {
    #[structopt(last = true)]
    args: Vec<XCString>,
    #[structopt(long, short = "e")]
    env: Vec<XCString>,
    #[structopt(long, short = "j")]
    json: bool,
    #[structopt(long, short = "f")]
    file: Option<PathBuf>,
    /// Capture stack trace for each syscall
    #[structopt(long, short = "b")]
    backtrace: bool,
    /// Child will inherit all environment vars visible to lxtrace
    #[structopt(long)]
    inherit_env: bool,
}

fn main() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStringExt;
    let mut opt: Opt = Opt::from_args();
    if opt.args.is_empty() {
        eprintln!("executable not provided");
        exit(1);
    }
    if opt.inherit_env {
        // TODO: probably this doesn't interact well with --env
        for (k, v) in std::env::vars_os() {
            let mut s = std::ffi::OsString::new();
            s.push(k);
            s.push("=");
            s.push(v);
            let cs = std::ffi::CString::new(s.into_vec())
                .expect("environment contains non-zero-terminated string");
            opt.env.push(XCString(cs));
        }
    }
    let (sender, receiver) = crossbeam::channel::unbounded();
    {
        let opt = opt.clone();
        unsafe {
            // we spawn new thread, because lxtrace will block it until child finishes
            std::thread::spawn(move || {
                let arg0 = opt.args[0].clone();
                let cmd_args = lxtrace::SpawnOptions {
                    exe: &arg0,
                    argv: &opt
                        .args
                        .iter()
                        .map(XCString::deref)
                        .map(|cstring| cstring.as_c_str())
                        .collect::<Vec<_>>(),
                    env: &opt
                        .env
                        .iter()
                        .map(XCString::deref)
                        .map(|cstring| cstring.as_c_str())
                        .collect::<Vec<_>>(),
                };
                let payload = lxtrace::Payload::Cmd(cmd_args);
                let settings = lxtrace::Settings {
                    capture_backtrace: opt.backtrace,
                };

                if let Err(e) = lxtrace::run(payload, settings, sender) {
                    eprintln!("{:?}", e);
                }
            });
        }
    }
    let mut out: Box<dyn std::io::Write> = match &opt.file {
        Some(path) => {
            let file = std::fs::File::create(path).context("failed to open log file")?;
            Box::new(std::io::BufWriter::new(file))
        }
        None => Box::new(std::io::stdout()),
    };
    loop {
        let event = match receiver.recv() {
            Ok(x) => x,
            Err(_) => {
                break;
            }
        };
        if opt.json {
            let s = serde_json::to_string(&event).expect("failed to serialize");
            writeln!(&mut *out, "{}", s)?;
        } else {
            print_event(event, &mut *out).ok();
        }
    }
    Ok(())
}
