use std::{
    io::{self, Read},
    thread,
};

use rust_tcp::Interface;

fn main() -> io::Result<()> {
    let mut i = Interface::new()?;
    let mut t1 = i.bind(9000)?;

    let h1 = thread::spawn(move || {
        while let Ok(mut stream) = t1.accept() {
            eprintln!("get connection on 9000");
            let n = stream.read(&mut [0]).unwrap();
            println!("read data");
            assert_eq!(n, 0);
        }
    });
    let _ = h1.join();

    Ok(())
}
