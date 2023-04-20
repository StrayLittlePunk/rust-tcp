pub mod tcp;

use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io::{self, Read, Write},
    sync::{Arc, Condvar, Mutex},
    thread,
};

use etherparse::Ipv4HeaderSlice;
use tun_tap::{Iface, Mode};

#[derive(Default)]
struct FooBar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}
type InterfaceHandle = Arc<FooBar>;

const SENDQUEUE_SIZE: usize = 1024;

pub struct Interface {
    cm: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct ConnectionManager {
    connections: HashMap<tcp::Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<tcp::Quad>>,
    terminate: bool,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.cm.as_mut().unwrap().manager.lock().unwrap().terminate = true;
        drop(self.cm.take());
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap();
    }
}

fn packet_loop(nic: Iface, cm: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];
    loop {
        // TODO: set a timeout for this recv for TCP timers or ConnectionManager::terminate
        let nbytes = nic.recv(buf.as_mut_slice())?;
        if nbytes == 0 {
            break;
        }
        //TODO: if self.terminate && Arc::get_strong_ref(cm) == 1; then tear down all connections and return

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
                        let datai = iph_len + tcph.slice().len();
                        let mut mg = cm.manager.lock().unwrap();
                        let m = &mut *mg;
                        let q = tcp::Quad {
                            src: (iph.source_addr(), tcph.source_port()),
                            dst: (iph.destination_addr(), tcph.destination_port()),
                        };
                        match m.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                eprintln!("got packet for known quad: {q:?}");
                                let a = c
                                    .get_mut()
                                    .on_packet(&nic, tcph, &buf[datai..nbytes])
                                    .unwrap();
                                //TODO compare before/after
                                drop(mg);
                                if a.contains(tcp::Available::READ) {
                                    cm.rcv_var.notify_all();
                                }
                                if a.contains(tcp::Available::WRITE) {
                                    // cm.snd_var.notify_all();
                                }
                            }
                            Entry::Vacant(e) => {
                                eprintln!("got packet for unknown quad: {q:?}");
                                if let Some(pending) = m.pending.get_mut(&tcph.destination_port()) {
                                    eprintln!("got packet for pending unknown quad: {q:?}");
                                    if let Some(c) = tcp::Connection::accept(
                                        &nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )
                                    .unwrap()
                                    {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(mg);
                                        cm.pending_var.notify_all();
                                        //TODO: wake up pending accept()
                                    }
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

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = Iface::without_packet_info("tun0", Mode::Tun)?;
        let cm: InterfaceHandle = Default::default();
        let jh = {
            let cm = cm.clone();
            thread::spawn(move || {
                if let Err(e) = packet_loop(nic, cm) {
                    eprintln!("packet loop has error: {e}");
                }
            })
            .into()
        };
        Ok(Self { cm: Some(cm), jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut cm = self.cm.as_mut().unwrap().manager.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
        }
        drop(cm);
        Ok(TcpListener {
            port,
            cm: self.cm.as_ref().unwrap().clone(),
        })
    }
}

pub struct TcpStream {
    quad: tcp::Quad,
    cm: InterfaceHandle,
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut cm = self.cm.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            ))?;
            if c.is_rev_closed() && c.incoming.is_empty() {
                // no more data to read, no need to block, because there won't be any more
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                //TODO: detect FIN and return nread == 0
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let hread = buf.len().min(head.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nread += hread;
                let tread = (buf.len() - nread).min(tail.len());
                buf[hread..hread + tread].copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }

            cm = self.cm.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.cm.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "stream was terminated unexpectedly",
        ))?;
        if c.unacked.len() >= SENDQUEUE_SIZE {
            //TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        let nwrite = buf.len().min(SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(&buf[..nwrite]);
        // TODO: wrak up writer
        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.cm.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "stream was terminated unexpectedly",
        ))?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            //TODO block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        // TODO: send FIN on cm.connections[quad]
        //  unimplemented!()
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.cm.manager.lock().unwrap();
        if let Some(c) = cm.connections.remove(&self.quad) {
            // TODO: send FIN on cm.connections[quad]
            //    unimplemented!()
        }
    }
}

pub struct TcpListener {
    port: u16,
    cm: InterfaceHandle,
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut m = self.cm.manager.lock().unwrap();
        loop {
            if let Some(quad) = m
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    cm: self.cm.clone(),
                });
            }
            m = self.cm.pending_var.wait(m).unwrap();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.cm.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for quad in pending {
            //TODO: terminate cm.connections[quad]
            unimplemented!()
        }
    }
}
