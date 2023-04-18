use std::io;

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun_tap::Iface;

#[derive(Debug)]
pub enum State {
    Closed,
    Listen,
    SyncRcvd,
    Estab,
}

#[derive(Debug)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of Send Sequence Space (RFC 793 S3.2) F4
///
/// ```
///              1         2          3          4
///         ----------|----------|----------|----------
///                SND.UNA    SND.NXT    SND.UNA
///                                     +SND.WND
///
///   1 - old sequence numbers which have been acknowledged
///   2 - sequence numbers of unacknowledged data
///   3 - sequence numbers allowed for new data transmission
///   4 - future sequence numbers which are not yet allowed
/// ```
#[derive(Debug)]
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    ///  send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    ///  initial send sequence number
    iss: u32,
}

///	State of Receive Sequence Space (RFC 793 S3.2) F5
///
/// ```
///                 1          2          3
///             ----------|----------|----------
///                    RCV.NXT    RCV.NXT
///                              +RCV.WND
///
///  1 - old sequence numbers which have been acknowledged
///  2 - sequence numbers allowed for new reception
///  3 - future sequence numbers which are not yet allowed
/// ```
#[derive(Debug)]
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    ///	receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn on_packet<'a>(
        &mut self,
        nic: &Iface,
        eth_flags: u16,
        eth_proto: u16,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        Ok(())
    }
    pub fn accept<'a>(
        nic: &Iface,
        eth_flags: u16,
        eth_proto: u16,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN
            return Ok(None);
        }

        let iss = 0;
        let c = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                irs: tcph.sequence_number(),
                up: false,
            },
        };

        // need to start establishing a connection
        let mut syn_ack = TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;

        syn_ack.syn = true;
        syn_ack.ack = true;

        let ip = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            IpNumber::Tcp as u8,
            iph.destination_addr().octets(),
            iph.source_addr().octets(),
        );
        // kernel does this for us
        //     syn_ack.checksum = syn_ack
        //        .calc_checksum_ipv4(&ip, &[])
        //        .expect("failed to compute checksum");
        let eth_flag_proto = (eth_flags as u32) << 16 | eth_proto as u32;
        (&mut buf[..4]).copy_from_slice(eth_flag_proto.to_be_bytes().as_slice());

        ip.write(&mut &mut buf[4..ip.header_len() + 4])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        syn_ack
            .write(
                &mut &mut buf
                    [ip.header_len() + 4..4 + ip.header_len() + syn_ack.header_len() as usize],
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        nic.send(&buf[0..4 + ip.header_len() + syn_ack.header_len() as usize])?;
        eprintln!(
            "{}:{} -> {}:{} 0x{:x} B of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len()
        );
        Ok(Some(c))
    }
}

// ack c7, 83, 1d, 1a
// 50, 12, 00, 0a
/*
45, 00, 00, 3c
55, 0e, 40, 00
40, 06, 8c, 59
c0, a8, 6c, 01
c0, a8, 6c, 02
 */
