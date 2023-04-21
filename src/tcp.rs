use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::{collections::VecDeque, io};

use bitflags::bitflags;
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, WriteError};
use tun_tap::Iface;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct Available: u8 {
        const READ =  0b00000001;
        const WRITE = 0b00000010;
    }
}

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
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: Ipv4Header,
    tcp: TcpHeader,
    timer: Timers,

    pub(crate) state: State,
    pub(crate) closed: bool,
    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    // keep track of the sequence number we used for the fin if we have sent
    closed_at: Option<u32>,
}

#[derive(Debug)]
struct Timers {
    last_send: Instant,
    send_tiems: BTreeMap<u32, Instant>,
    srtt: Duration,
}

impl Connection {
    pub(crate) fn is_rev_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: any state after recv FIN, so alose CLOSE-WAIT LAST-ACK  CLOSED CLOSING
            true
        } else {
            false
        }
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SyncRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "already closing",
                ))
            }
        }

        Ok(())
    }

    fn availablity(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rev_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        //TODO: take into account self.state
        //TODO: set Available::WRITE
        a
    }

    fn have_sent_fin(&self) -> bool {
        match self.state {
            State::SyncRcvd | State::Estab => false,
            State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
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
    wnd: u32,
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
    wnd: u32,
    ///	receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub(crate) fn on_tick(&mut self, nic: &Iface) -> io::Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked, no need to transmit anything
            return Ok(());
        }

        let nunacked = self.send.nxt.wrapping_sub(self.send.una);
        let unsent = self.unacked.len() - nunacked as usize;

        let waited_for = self
            .timer
            .send_tiems
            .range(self.send.una..)
            .next()
            .map(|(_, i)| i.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > Duration::from_secs(1)
                && waited_for > Duration::from_nanos((15 * self.timer.srtt.as_nanos() / 10) as u64)
        } else {
            false
        };

        if should_retransmit {
            // we should retransimt things!
            let resend = self.unacked.len().min(self.send.wnd as usize);
            if resend < self.send.wnd as usize && self.closed {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            let payload = self.unacked.make_contiguous().to_vec();
            self.write(nic, self.send.una, &payload[..resend])?;
            self.send.nxt = self.send.una.wrapping_add(self.send.wnd);
        } else {
            // we should send new data if we have new data and space in the window
            if unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd - nunacked;
            if allowed == 0 {
                return Ok(());
            }

            let send = unsent.min(allowed as usize);
            if send < allowed as usize && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(unsent as u32));
            }
            let payload = self.unacked.make_contiguous().to_vec();
            self.write(
                nic,
                self.send.nxt,
                &payload[nunacked as usize..(nunacked as usize + send)],
            )?;
        }

        // decide if it needs to send something
        // send it

        // if FIN, enter FIN-WAIT-1

        Ok(())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &Iface,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
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
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd);
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
            println!("NOT OKEY");
            self.write(nic, self.send.nxt, &[])?;
            return Ok(self.availablity());
        }
        //self.recv.nxt = seqn.wrapping_add(slen);

        //TODO: if _not_ acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            println!("NOT ACK");
            self.recv.nxt = seqn.wrapping_add(slen);
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availablity());
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
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                if !self.unacked.is_empty() {
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    let acked_data_end = self
                        .unacked
                        .len()
                        .min(ackn.wrapping_sub(data_start) as usize);
                    self.unacked.drain(..acked_data_end);
                    self.timer.send_tiems.retain(|seq, sent| {
                        if is_between_wrapped(self.send.una, *seq, ackn) {
                            let srtt = self.timer.srtt.as_nanos();
                            self.timer.srtt = Duration::from_nanos(
                                ((8 * srtt + 2 * sent.elapsed().as_nanos()) / 10) as u64,
                            );
                            false
                        } else {
                            true
                        }
                    });
                }
                self.send.una = ackn;
            }
            // TODO: prune self.unacked
            // TODO: if unacked empty and waiting flush, notify
            // TODO: update window

            // we don't support Write yet
            if let State::Estab = self.state {
                // TODO: needs to be stored in the retransmission queue !
                self.tcp.fin = true;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // out FIN has been ACKed
                    self.state = State::FinWait2
                }
            }
        }

        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_at = (self.recv.nxt - seqn) as usize;
                if unread_data_at > data.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, data.len() + 1);
                    unread_data_at = 0;
                }
                println!(
                    "reading data at from {} ({}:{}) from {:?}",
                    unread_data_at, self.recv.nxt, seqn, data
                );
                // TODO: only read stuff we haven't read
                self.incoming.extend(&data[unread_data_at..]);

                //  Once the TCP takes responsibility for the data it advances
                //  RCV.NXT over the data accepted, and adjusts RCV.WND as
                //  apporopriate to the current buffer availability.  The total of
                //  RCV.NXT and RCV.WND should not be reduced.
                self.recv.nxt = seqn.wrapping_add(tcph.fin().into());

                //  Send an acknowledgment of the form:
                //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // TODO: maybe just tick to piggyback ack on data
                self.write(nic, self.send.nxt, &[])?;

                /*
                if let State::Estab = self.state {
                    // now let's terminate the connection
                    //TODO: needs to be stored in the retransmission queue!
                    self.tcp.fin = true;
                    self.write(nic, &[])?;
                    self.state = State::FinWait1;
                }
                */
            }
        }
        eprintln!("run timewait {:?} {}", self.state, tcph.fin());
        if let State::FinWait2 = self.state {
            if tcph.fin() {
                self.recv.nxt = self.recv.nxt.wrapping_add(1);
                // we're done with the connection!
                self.write(nic, self.send.nxt, &[])?;
                self.state = State::TimeWait;
            }
        }
        Ok(self.availablity())
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
                wnd: tcph.window_size() as u32,
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
            tcp: TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd as u16),
            incoming: Default::default(),
            unacked: Default::default(),
            closed: false,
            timer: Timers {
                last_send: Instant::now(),
                send_tiems: Default::default(),
                srtt: Duration::from_secs(1 * 60),
            },
            closed_at: None,
        };

        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, c.send.nxt, &[])?;
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

    fn write(&mut self, nic: &Iface, seqn: u32, payload: &[u8]) -> io::Result<usize> {
        use std::io::{Cursor, Write};
        let mut cursor = Cursor::new([0u8; 1500]);
        self.tcp.sequence_number = seqn;
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

        let next_seq = seqn.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        self.timer.send_tiems.insert(seqn, Instant::now());

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

        self.write(nic, self.send.nxt, &[])?;
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
