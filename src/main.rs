use ktrace::{self, DecodedArg, Event, EventPayload};
use structopt::StructOpt;
use std::process::exit;

fn print_data(arg: DecodedArg) {
    match arg {
        DecodedArg::Num(num) => print!("{}", num),
        DecodedArg::Handle(raw_fd, fd_ray) => {
            print!("{}", raw_fd);
            if let Some(ray) = fd_ray {
                print!("@{}", ray);
            }
        }
        DecodedArg::String(s) => {
            print!("\"{}\"", s);
        }
        DecodedArg::Flags(_, _) => {
            print!("TODO: flags");
        }
        DecodedArg::Unknown => {
            print!("<unknown>");
        }
    }
}

fn print_sysenter_event(ev: Event) {
    match ev.payload {
        EventPayload::Sysenter(raw_data, data) => match data {
            Some(data) => {
                print!("[{}]: syscall {}(", ev.pid, &data.name);
                for arg in data.args_decoded {
                    print_data(arg);
                    print!(","); // TODO properly put commas and spacing
                }
                println!(")");
            }
            None => println!(
                "[{}]: unknown syscall {}({}, {}, {}, {}, {}, {})",
                ev.pid,
                raw_data.syscall_id,
                raw_data.args[0],
                raw_data.args[1],
                raw_data.args[2],
                raw_data.args[3],
                raw_data.args[4],
                raw_data.args[5]
            ),
        },
        _ => unreachable!(),
    }
}

fn print_event(event: Event) {
    match event.payload {
        EventPayload::Attach => {
            println!("[{}]: attached", event.pid);
        }
        EventPayload::Exit(exit_code) => {
            println!("[{}]: exited, code={}", event.pid, exit_code);
        }
        EventPayload::Sysenter(_, _) => print_sysenter_event(event),
        EventPayload::Eos => unreachable!(),
    }
}

#[derive(StructOpt)]
struct Opt {
    #[structopt(long = "arg", short = "a")]
    args: Vec<String>,
    #[structopt(long = "env", short = "e")]
    env: Vec<String>,
}

fn split_env_item(s: &str) -> (String, String) {
    if !s.contains('=') {
        eprintln!("env var must be passed as NAME=VALUE");
        exit(1);
    }
    let mut it = s.splitn(2, '=');

    (it.next().unwrap().to_string(), it.next().unwrap().to_string())
}

fn main() {
    let opt: Opt = Opt::from_args();
    if opt.args.is_empty() {
        eprintln!("executable not provided");
        exit(1);
    }
    let (sender, receiver) = crossbeam::channel::unbounded();
    let cmd_args = ktrace::SpawnOptions {
        argv: opt.args,
        env: opt
            .env
            .into_iter()
            .map(|p| split_env_item(&p))
            .collect(),
    };
    let payload = ktrace::Payload::Cmd(cmd_args);
    unsafe {
        // we spawn new thread, because kthread will block it until child finishes
        std::thread::spawn(move || {
            ktrace::run(payload, sender).unwrap();
        });
    }
    loop {
        let event = match receiver.recv() {
            Ok(x) => x,
            Err(_) => break,
        };
        print_event(event);
    }
}
