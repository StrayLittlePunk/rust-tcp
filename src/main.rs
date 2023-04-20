use std::{
    io::{self, Read},
    thread,
};

use rust_tcp::Interface;

fn main() -> io::Result<()> {
    let mut i = Interface::new()?;
    let mut t1 = i.bind(9000)?;

    let h1 = thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok(mut stream) = t1.accept() {
            eprintln!("get connection on 9000");
            loop {
                let n = stream.read(&mut buf).unwrap();
                println!("read {}b data", n);
                if n != 0 {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                } else {
                    println!("no more data");
                    break;
                }
            }
        }
    });
    let _ = h1.join();

    Ok(())
}
