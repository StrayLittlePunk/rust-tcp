use std::net::Ipv4Addr;
use std::{collections::VecDeque, io};

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, WriteError};
use tun_tap::Iface;

#[derive(Debug)]
pub enum State {
    SyncRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            Self::SyncRcvd => false,
            Self::Estab | Self::FinWait1 | Self::FinWait2 | Self::TimeWait => true,
        }
    }
}

#[derive(Debug)]
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: Ipv4Header,
    tcp: TcpHeader,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
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
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        //
        // valid segment check
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let nxt = self.recv.nxt.wrapping_sub(1);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(nxt, seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(nxt, seqn, wend)
                && !is_between_wrapped(nxt, seqn + slen - 1, wend)
            {
                false
            } else {
                true
            }
        };
        if !okay {
            self.write(nic, &[])?;
            return Ok(());
        }
        self.recv.nxt = seqn.wrapping_add(slen);

        //TODO: if _not_ acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            return Ok(());
        }

        let ackn = tcph.acknowledgment_number();

        if let State::SyncRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at lease one acked byte, and we have only
                // sent one byte (the SYN)
                self.state = State::Estab;
            } else {
                // TODO: reset <SEQ=SEG.ACK><CTL=RST>
            }
        }
        //    // expect to get an ACK for our SYN
        //    if !tcph.ack() {
        //        return Ok(());
        //    }
        //    // now let's terminate the connection
        //    //TODO: needs to be stored in the retransmission queue!
        //    self.tcp.fin = true;
        //    self.write(nic, &[])?;
        //    self.state = State::FinWait1;
        //}
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            //TODO
            assert!(data.is_empty());

            if let State::Estab = self.state {
                // now let's terminate the connection
                //TODO: needs to be stored in the retransmission queue!
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }
        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // out FIN has been ACKed
                self.state = State::FinWait2
            }
        }
        if let State::FinWait2 = self.state {
            if tcph.fin() {
                // we're done with the connection!
                self.write(nic, &[])?;
                self.state = State::TimeWait;
            }
        }
        Ok(())
    }

    pub fn accept<'a>(
        nic: &Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // only expected SYN
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
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
            ip: Ipv4Header::new(
                0,
                64,
                IpNumber::Tcp as u8,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            ),
            tcp: TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            incoming: Default::default(),
            unacked: Default::default(),
        };

        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, &[])?;
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

    fn write(&mut self, nic: &Iface, payload: &[u8]) -> io::Result<usize> {
        use std::io::{Cursor, Write};
        let mut cursor = Cursor::new([0u8; 1500]);
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = cursor
            .get_ref()
            .len()
            .min(self.tcp.header_len() as usize + payload.len() + self.ip.header_len() as usize);

        self.ip
            .set_payload_len(size - self.ip.header_len() as usize)
            .expect("invalid tcp payload len for too big");

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, payload)
            .expect("failed to compute checksum");

        // if s/without_packet_info/new/:
        // let eth_flag_proto = (eth_flags as u32) << 16 | eth_proto as u32;
        // (&mut buf[..4]).copy_from_slice(eth_flag_proto.to_be_bytes().as_slice());

        if let Err(e) = self.ip.write(&mut cursor) {
            let error = match e {
                WriteError::IoError(e) => e,
                WriteError::SliceTooSmall(len) => io::Error::new(
                    io::ErrorKind::Interrupted,
                    format!("slice too small with length: {len}"),
                ),
                WriteError::ValueError(v) => io::Error::new(io::ErrorKind::Other, v.to_string()),
            };
            return Err(error);
        };
        self.tcp.write(&mut cursor)?;
        let payload_bytes = cursor.write(payload)?;
        let buf_length = cursor.position() as usize;
        nic.send(&cursor.into_inner()[..buf_length])?;

        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        Ok(payload_bytes)
    }

    fn send_rst<'a>(&mut self, nic: &Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        //  If the connection is in a synchronized state (ESTABLISHED,
        //  FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //  any unacceptable segment (out of window sequence number or
        //  unacceptible acknowledgment number) must elicit only an empty
        //  acknowledgment segment containing the current send-sequence number
        //  and an acknowledgment indicating the next sequence number expected
        //  to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;

        self.write(nic, &[])?;
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
