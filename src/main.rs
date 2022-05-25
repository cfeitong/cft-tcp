mod tcp;

use std::{collections::HashMap, net::Ipv4Addr};

use color_eyre::Result;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut tcp_conn: HashMap<Quad, tcp::State> = HashMap::new();
    loop {
        let mut buf = [0u8; 1504];
        let read = nic.recv(&mut buf[..])?;
        let _flag = u16::from_be_bytes([buf[0], buf[1]]);
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        if protocol != 0x800 {
            // not ipv4
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..read]) {
            Ok(ip_hdr) => {
                if ip_hdr.protocol() != 0x6 {
                    continue; // not tcp
                }
                let ipv4_hdr_size = ip_hdr.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ipv4_hdr_size..read]) {
                    Ok(tcp_hdr) => {
                        let tcp_hdr_size = tcp_hdr.slice().len();
                        let data = &buf[4 + ipv4_hdr_size + tcp_hdr_size..read];
                        let quad = Quad {
                            src: (ip_hdr.source_addr(), tcp_hdr.source_port()),
                            dst: (ip_hdr.source_addr(), tcp_hdr.destination_port()),
                        };
                        tcp_conn.entry(quad).or_default().on_packet(
                            ip_hdr.clone(),
                            tcp_hdr.clone(),
                            data,
                        );
                        println!(
                            "from {}:{} to {}:{}",
                            ip_hdr.source_addr(),
                            tcp_hdr.source_port(),
                            ip_hdr.destination_addr(),
                            tcp_hdr.destination_port()
                        );
                    }
                    Err(err) => {
                        eprintln!("corrupted tcp frame: err={err:?}");
                    }
                }
            }
            Err(err) => {
                eprintln!("corrupted ipv4 packet: err={:?}", err);
            }
        }
    }

    Ok(())
}
