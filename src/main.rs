use std::{collections::HashMap, io};

use etherparse::Ipv4HeaderSlice;
use tun_tap::{Iface, Mode};

use rust_tcp::tcp;

fn main() -> io::Result<()> {
    let nic = Iface::without_packet_info("tun0", Mode::Tun).expect("failed to create tun");
    let mut buf = [0u8; 1500];
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = HashMap::new();
    loop {
        let nbytes = nic.recv(buf.as_mut_slice())?;
        if nbytes == 0 {
            break;
        }
        // if s/without_packet_info/new/:
        // let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != 0x0800 {
        //     // no ipv4
        //     continue;
        // }

        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let proto = iph.protocol();
                if proto != 0x06 {
                    // not tcp
                    continue;
                }

                let iph_len = iph.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[iph_len..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph_len + tcph.slice().len();
                        match connections.entry(tcp::Quad {
                            src: (iph.source_addr(), tcph.source_port()),
                            dst: (iph.destination_addr(), tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&nic, iph, tcph, &buf[datai..nbytes])
                                    .unwrap();
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) =
                                    tcp::Connection::accept(&nic, iph, tcph, &buf[datai..nbytes])
                                        .unwrap()
                                {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(_) => {
                //   eprintln!("ignoring weird ip packet {:?}", e);
            }
        }
    }
    Ok(())
}
