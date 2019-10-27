use anyhow::Context;
use ktrace::{self, Event, EventPayload, Value};
use std::{io::Write, path::PathBuf, process::exit};
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
            let s = String::from_utf8_lossy(&*buf);
            write!(wr, "\"{}\"", s)?;
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

fn print_syscall_event(
    ev: Event,
    kind: SyscallEvent,
    wr: &mut dyn Write,
) -> std::io::Result<()> {
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
                    for arg in &data.args {
                        print_data(arg, wr)?;
                        write!(wr, ",")?; // TODO properly put commas and spacing
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
                        for (i,frame) in thread.frames().iter().enumerate() {
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

#[derive(StructOpt)]
struct Opt {
    #[structopt(last = true)]
    args: Vec<String>,
    #[structopt(long, short = "e")]
    env: Vec<String>,
    #[structopt(long, short = "j")]
    json: bool,
    #[structopt(long, short = "f")]
    file: Option<PathBuf>,
    /// Capture stack trace for each syscall
    #[structopt(long, short = "b")]
    backtrace: bool,
}

fn split_env_item(s: &str) -> (String, String) {
    if !s.contains('=') {
        eprintln!("env var must be passed as NAME=VALUE");
        exit(1);
    }
    let mut it = s.splitn(2, '=');

    (
        it.next().unwrap().to_string(),
        it.next().unwrap().to_string(),
    )
}

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    if opt.args.is_empty() {
        eprintln!("executable not provided");
        exit(1);
    }
    let (sender, receiver) = crossbeam::channel::unbounded();
    let cmd_args = ktrace::SpawnOptions {
        argv: opt.args,
        env: opt.env.into_iter().map(|p| split_env_item(&p)).collect(),
    };
    let payload = ktrace::Payload::Cmd(cmd_args);
    let settings = ktrace::Settings {
        capture_backtrace: opt.backtrace,
    };
    unsafe {
        // we spawn new thread, because ktrace will block it until child finishes
        std::thread::spawn(move || {
            if let Err(e) = ktrace::run(payload, settings, sender) {
                eprintln!("{:?}", e);
            }
        });
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
