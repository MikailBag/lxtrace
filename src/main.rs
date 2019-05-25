use ktrace;

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
        println!("got {:?}", event);
    }
}
