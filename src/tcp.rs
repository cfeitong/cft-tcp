use etherparse::{Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::io;

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

impl Default for Connection {
    fn default() -> Self {
        Connection {
            state: State::Listen,
        }
    }
}

impl Connection {
    pub fn on_packet(
        &mut self,
        ip_hdr: Ipv4HeaderSlice,
        tcp_hdr: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match &self.state {
            State::Closed => Ok(0),
            State::Listen => {
                if !tcp_hdr.syn() {
                    return Ok(0);
                }

                self.rx.irs = tcp_hdr.sequence_number();
                self.rx.nxt = tcp_hdr.sequence_number() + 1;
                self.rx.wnd = tcp_hdr.window_size();

                self.tx.iss = 0;
                self.tx.una = 0;
                self.tx.nxt = self.tx.una + 1;
                self.tx.wnd = 10;

                let mut syn_ack = TcpHeader::new(
                    tcp_hdr.destination_port(),
                    tcp_hdr.source_port(),
                    self.tx.iss,
                    self.tx.wnd,
                );
                syn_ack.syn = true;
                syn_ack.ack = true;
                syn_ack.acknowledgment_number = self.rx.nxt;
                let mut ip = Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpNumber::Tcp,
                    ip_hdr.destination_addr().octets(),
                    ip_hdr.source_addr().octets(),
                );
                let written = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten).map_err(|err| match err {
                        etherparse::WriteError::IoError(err) => err,
                        _ => unimplemented!(),
                    })?;
                    syn_ack.write(&mut unwritten)?;
                    unwritten.len()
                };
                self.state = State::SynRcvd;
                Ok(written)
            }
            State::SynRcvd => todo!(),
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
}
