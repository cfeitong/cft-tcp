use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io::{self, Cursor};
use std::num::Wrapping;
use tracing::debug;
use tun_tap::Iface;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

impl State {
    fn is_sync(&self) -> bool {
        match self {
            State::SynRcvd | State::SynSent | State::Listen => false,
            _ => true,
        }
    }
}

pub struct Connection {
    state: State,
    tx: SendSequence,
    rx: ReceiveSequence,
    ip: Ipv4Header,
    tcp: TcpHeader,
    buf: Cursor<[u8; 1500]>,
}

// Send Sequence Space

//                   1         2          3          4
//              ----------|----------|----------|----------
//                     SND.UNA    SND.NXT    SND.UNA
//                                          +SND.WND

//        1 - old sequence numbers which have been acknowledged
//        2 - sequence numbers of unacknowledged data
//        3 - sequence numbers allowed for new data transmission
//        4 - future sequence numbers which are not yet allowed
//
// Send Sequence Variables

//     SND.UNA - send unacknowledged
//     SND.NXT - send next
//     SND.WND - send window
//     SND.UP  - send urgent pointer
//     SND.WL1 - segment sequence number used for last window update
//     SND.WL2 - segment acknowledgment number used for last window
//               update
//     ISS     - initial send sequence number
struct SendSequence {
    una: Wrapping<u32>,
    nxt: Wrapping<u32>,
    wnd: u16,
    up: bool,
    wl1: usize,
    wl2: usize,
    iss: u32,
}

// Receive Sequence Space

//                        1          2          3
//                    ----------|----------|----------
//                           RCV.NXT    RCV.NXT
//                                     +RCV.WND

//         1 - old sequence numbers which have been acknowledged
//         2 - sequence numbers allowed for new reception
//         3 - future sequence numbers which are not yet allowed

// Receive Sequence Variables

//       RCV.NXT - receive next
//       RCV.WND - receive window
//       RCV.UP  - receive urgent pointer
//       IRS     - initial receive sequence number

struct ReceiveSequence {
    nxt: Wrapping<u32>,
    wnd: u16,
    up: bool,
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut Iface,
        ip_hdr: Ipv4HeaderSlice,
        tcp_hdr: TcpHeaderSlice,
    ) -> io::Result<Option<Self>> {
        if !tcp_hdr.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd = tcp_hdr.window_size();
        let tcp = TcpHeader::new(tcp_hdr.destination_port(), tcp_hdr.source_port(), iss, wnd);
        let ip = Ipv4Header::new(
            tcp.header_len(),
            64,
            etherparse::IpNumber::Tcp,
            ip_hdr.destination_addr().octets(),
            ip_hdr.source_addr().octets(),
        );
        let mut c = Connection {
            state: State::SynRcvd,
            tx: SendSequence {
                una: Wrapping(iss),
                nxt: Wrapping(iss + 1),
                wnd: tcp_hdr.window_size(),
                up: false,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rx: ReceiveSequence {
                nxt: Wrapping(tcp_hdr.sequence_number()) + Wrapping(1),
                wnd: tcp_hdr.window_size(),
                up: false,
                irs: tcp_hdr.sequence_number(),
            },
            tcp,
            ip,
            buf: Cursor::new([0; 1500]),
        };

        let mut tcp = &mut c.tcp;
        tcp.syn = true;
        tcp.ack = true;
        c.send(nic, &[])?;
        Ok(Some(c))
    }

    fn send(&mut self, nic: &mut Iface, payload: &[u8]) -> io::Result<usize> {
        let mut tcp = &mut self.tcp;
        let buf = &mut self.buf;
        buf.set_position(0);
        tcp.sequence_number = self.tx.nxt.0;
        tcp.acknowledgment_number = self.rx.nxt.0;
        let ip = &mut self.ip;
        ip.set_payload_len(tcp.header_len() as usize + payload.len())
            .expect("ip header too large");
        let checksum = tcp
            .calc_checksum_ipv4(&ip, &[])
            .expect("fail to calculate tcp checksum");
        tcp.checksum = checksum;
        let written = {
            ip.write(buf).map_err(|err| match err {
                etherparse::WriteError::IoError(err) => err,
                _ => unimplemented!(),
            })?;
            tcp.write(buf)?;
            buf.position() as usize
        };
        self.tx.nxt += payload.len() as u32;
        if self.tcp.syn {
            self.tx.nxt += 1;
        }
        if self.tcp.fin {
            self.tx.nxt += 1;
        }
        nic.send(&buf.get_ref()[..written])?;
        Ok(payload.len())
    }

    fn send_rst(&mut self, nic: &mut Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.send(nic, &[])?;
        Ok(())
    }

    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_hdr: Ipv4HeaderSlice,
        tcp_hdr: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        if let Err(err) = self.check_acceptable_ack(tcp_hdr.acknowledgment_number()) {
            debug!(error=?err, "invalid acknowledgment number");
            if !self.state.is_sync() {
                self.send_rst(nic)?;
            }
            return Ok(0);
        }
        if let Err(err) = self.check_valid_segment(&tcp_hdr, data.len()) {
            debug!(error=?err, "invalid segment");
            if !self.state.is_sync() {
                self.send_rst(nic)?;
            }
            return Ok(0);
        }
        match &self.state {
            State::Closed => Ok(0),
            State::Listen => Ok(0),
            State::SynRcvd => {
                if !tcp_hdr.ack() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "must get an ack",
                    ));
                }
                self.state = State::Established;
                Ok(0)
            }
            State::SynSent => todo!(),
            State::Established => todo!(),
            State::FinWait1 => todo!(),
            State::FinWait2 => todo!(),
            State::Closing => todo!(),
            State::TimeWait => todo!(),
            State::CloseWait => todo!(),
            State::LastAck => todo!(),
        }
    }

    // copied from rfc793 page 24

    //      A new acknowledgment (called an "acceptable ack"), is one for which
    //   the inequality below holds:

    //     SND.UNA < SEG.ACK =< SND.NXT
    fn check_acceptable_ack(&self, ackn: u32) -> io::Result<()> {
        if is_between(self.tx.una + Wrapping(1), self.tx.nxt, ackn) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ackn is out of range",
            ))
        }
    }

    // copied frmo rfc793 page 25

    // Segment Receive  Test
    // Length  Window
    // ------- -------  -------------------------------------------

    //    0       0     SEG.SEQ = RCV.NXT

    //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

    //   >0       0     not acceptable

    //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    fn check_valid_segment(&self, tcp_hdr: &TcpHeaderSlice, slen: usize) -> io::Result<()> {
        let seqn = tcp_hdr.sequence_number();
        if slen == 0 && tcp_hdr.window_size() == 0 {
            if seqn != self.rx.nxt.0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seg.seq should equals rcv.nxt if  seg.len = 0 and seg.wnd = 0",
                ));
            }
        }
        if slen > 0 && tcp_hdr.window_size() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seg.wnd should not be 0 if seg.len > 0",
            ));
        }
        let end = self.rx.nxt + Wrapping(self.rx.wnd as u32);
        if is_between(self.rx.nxt, end - Wrapping(1), seqn) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seqn is out of range",
            ))
        }
    }
}

fn is_between(start: Wrapping<u32>, end: Wrapping<u32>, val: u32) -> bool {
    let val = Wrapping(val);
    if start < end {
        val >= start && val <= end
    } else {
        val >= start || val <= end
    }
}
