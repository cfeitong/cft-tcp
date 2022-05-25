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

impl Default for State {
    fn default() -> Self {
        State::Listen
    }
}

impl State {
    pub fn on_packet(
        &mut self,
        ip_hdr: Ipv4HeaderSlice,
        tcp_hdr: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        match *self {
            State::Closed => {
                unimplemented!()
            }
            State::Listen => {
                if !tcp_hdr.syn() {
                    return;
                }
                let mut syn_ack =
                    TcpHeader::new(tcp_hdr.destination_port(), tcp_hdr.source_port(), 0, 0);
                syn_ack.syn = true;
                syn_ack.ack = true;
                let mut ip = Ipv4Header::new(
                    syn_ack.header_len(),
                    64,
                    etherparse::IpNumber::Tcp,
                    ip_hdr.destination_addr().octets(),
                    ip_hdr.source_addr().octets(),
                );
                let written = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten)?;
                    syn_ack.write(&mut unwritten)?;
                    unwritten.len()
                };
                *self = State::SynRcvd;
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
