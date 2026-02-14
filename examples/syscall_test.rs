use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== Syscall Test Program ===");
    
    // 1. File I/O syscalls
    test_file_io();
    
    // 2. Process operations
    test_process_ops();
    
    // 3. Memory operations (implicit via allocation)
    test_memory_ops();
    
    // 4. Thread operations
    test_thread_ops();
    
    println!("=== Test Complete ===");
}

fn test_file_io() {
    println!("Testing file I/O...");
    
    // write syscall
    let mut file = File::create("/tmp/strace_test.txt").expect("Failed to create file");
    file.write_all(b"Hello from strace test!\n").expect("Failed to write");
    file.write_all(b"Second line of data.\n").expect("Failed to write second line");
    drop(file);
    
    // open, read, close syscalls
    let mut file = File::open("/tmp/strace_test.txt").expect("Failed to open file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Failed to read");
    println!("Read {} bytes", contents.len());
    drop(file);
    
    // Additional open with flags
    let _file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/tmp/strace_test2.txt")
        .expect("Failed to open with options");
    
    // unlink syscall
    std::fs::remove_file("/tmp/strace_test.txt").ok();
    std::fs::remove_file("/tmp/strace_test2.txt").ok();
}

fn test_process_ops() {
    println!("Testing process operations...");
    
    // fork + execve via Command
    let output = Command::new("/bin/echo")
        .arg("Hello")
        .arg("from")
        .arg("child")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn");
    
    // wait syscall
    let result = output.wait_with_output().expect("Failed to wait");
    println!("Child exited with: {:?}", result.status);
    
    // Another command to generate more syscalls
    let output = Command::new("/bin/sleep")
        .arg("0.1")
        .status()
        .expect("Failed to run sleep");
    println!("Sleep exited: {:?}", output);
}

fn test_memory_ops() {
    println!("Testing memory operations...");
    
    // Allocate and deallocate memory (triggers mmap/munmap)
    let mut vec = Vec::with_capacity(1024 * 1024); // 1MB
    for i in 0..1000 {
        vec.push(i);
    }
    println!("Allocated vector with {} elements", vec.len());
    drop(vec);
    
    // Box allocation
    let boxed = Box::new([0u8; 4096]);
    println!("Boxed {} bytes", boxed.len());
}

fn test_thread_ops() {
    println!("Testing thread operations...");
    
    // clone syscall (for thread creation)
    let handle = thread::spawn(|| {
        println!("Hello from spawned thread!");
        thread::sleep(Duration::from_millis(50));
        println!("Thread finishing...");
        42
    });
    
    // join (wait for thread)
    let result = handle.join().expect("Thread panicked");
    println!("Thread returned: {}", result);
}
