use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io::{self, Cursor, Write};
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

pub struct Connection {
    state: State,
    tx: SendSequence,
    rx: ReceiveSequence,
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
    una: u32,
    nxt: u32,
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
    nxt: u32,
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
        let c = Connection {
            state: State::SynRcvd,
            tx: SendSequence {
                una: iss,
                nxt: iss + 1,
                wnd: tcp_hdr.window_size(),
                up: false,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rx: ReceiveSequence {
                nxt: tcp_hdr.sequence_number() + 1,
                wnd: tcp_hdr.window_size(),
                up: false,
                irs: tcp_hdr.sequence_number(),
            },
        };
        let mut syn_ack = TcpHeader::new(
            tcp_hdr.destination_port(),
            tcp_hdr.source_port(),
            c.tx.iss,
            c.tx.wnd,
        );
        syn_ack.syn = true;
        syn_ack.ack = true;
        syn_ack.acknowledgment_number = c.rx.nxt;
        let mut ip = Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpNumber::Tcp,
            ip_hdr.destination_addr().octets(),
            ip_hdr.source_addr().octets(),
        );
        ip.set_payload_len(syn_ack.header_len() as usize)
            .expect("ip header too large");
        let checksum = syn_ack
            .calc_checksum_ipv4(&ip, &[])
            .expect("fail to calculate tcp checksum");
        syn_ack.checksum = checksum;
        let mut buf = Cursor::new([0u8; 1500]);
        let written = {
            ip.write(&mut buf).map_err(|err| match err {
                etherparse::WriteError::IoError(err) => err,
                _ => unimplemented!(),
            })?;
            syn_ack.write(&mut buf)?;
            buf.position() as usize
        };
        let buf = buf.into_inner();
        nic.send(&buf[..written])?;
        Ok(Some(c))
    }

    pub fn on_packet(
        &mut self,
        nic: &mut Iface,
        ip_hdr: Ipv4HeaderSlice,
        tcp_hdr: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        self.check_acceptable_ack(tcp_hdr.acknowledgment_number())?;
        self.check_valid_segment(tcp_hdr.sequence_number())?;
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

    fn check_acceptable_ack(&self, ackn: u32) -> io::Result<()> {
        if is_between_wrapped(self.tx.una.wrapping_add(1), self.tx.nxt, ackn) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ackn is out of range",
            ))
        }
    }

    fn check_valid_segment(&self, seqn: u32) -> io::Result<()> {
        let end = self.rx.nxt.wrapping_add(self.rx.wnd as u32);
        if is_between_wrapped(self.rx.nxt, end.wrapping_sub(1), seqn) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seqn is out of range",
            ))
        }
    }
}

fn is_between_wrapped(start: u32, end: u32, val: u32) -> bool {
    if start < end {
        val >= start && val <= end
    } else {
        val >= start || val <= end
    }
}
