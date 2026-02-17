fn main() {
    let mut children = Vec::new();

    for i in 0..60 {
        let child = std::thread::spawn(move || {
            println!("Hello from thread {}", i);
            std::thread::sleep(std::time::Duration::from_secs(1));
        });
        children.push(child);
    }

    for child in children {
        child.join().unwrap();
    }
}
