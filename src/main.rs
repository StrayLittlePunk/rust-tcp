use std::io;

use tun_tap::{Iface, Mode};

fn main() -> io::Result<()> {
    let nic = Iface::new("tun0", Mode::Tun).expect("failed to create tun");
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(buf.as_mut_slice())?;
        if nbytes == 0 {
            break;
        }
        eprintln!("read {} bytes: {:?}", nbytes, &buf[..nbytes]);
    }
    Ok(())
}
