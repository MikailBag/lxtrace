use ktrace::{self, EventPayload};

fn child() {
    println!("child: hello, world");
}

fn main() {
    let (sender, receiver) = crossbeam::channel::unbounded();
    let payload = ktrace::Payload::Fn(Box::new(child));
    unsafe {
        std::thread::spawn(move || {
            ktrace::run(payload, sender).unwrap();
        });
    }
    loop {
        let event = match receiver.recv() {
            Ok(x) => x,
            Err(_) => break,
        };
        match event.payload {
            EventPayload::RawSysenter(_) => unreachable!(),
            EventPayload::Attach => {
                println!("[{}]: attached", event.pid);
            }
            EventPayload::Exit(exit_code) => {
                println!("[{}]: exited, code={}", event.pid, exit_code);
            }
            EventPayload::Sysenter(raw_data, data) => match data {
                Some(data) => {
                    println!("[{}]: syscall {}()", event.pid, &data.name);
                }
                None => println!(
                    "[{}]: unknown syscall {}({}, {}, {}, {}, {}, {})",
                    event.pid,
                    raw_data.syscall_id,
                    raw_data.args[0],
                    raw_data.args[1],
                    raw_data.args[2],
                    raw_data.args[3],
                    raw_data.args[4],
                    raw_data.args[5]
                ),
            },
            EventPayload::Eos => {}
        }
    }
}
