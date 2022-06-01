mod tcp;

use std::{collections::HashMap, net::Ipv4Addr};

use color_eyre::Result;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut tcp_conn: HashMap<Quad, tcp::Connection> = HashMap::new();
    loop {
        let mut buf = [0u8; 1500];
        let read = nic.recv(&mut buf[..])?;
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[0..read]) {
            Ok(ip_hdr) => {
                if ip_hdr.protocol() != 0x6 {
                    continue; // not tcp
                }
                let ipv4_hdr_size = ip_hdr.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[ipv4_hdr_size..read]) {
                    Ok(tcp_hdr) => {
                        let tcp_hdr_size = tcp_hdr.slice().len();
                        let data = &buf[ipv4_hdr_size + tcp_hdr_size..read];
                        let quad = Quad {
                            src: (ip_hdr.source_addr(), tcp_hdr.source_port()),
                            dst: (ip_hdr.source_addr(), tcp_hdr.destination_port()),
                        };
                        match tcp_conn.entry(quad) {
                            std::collections::hash_map::Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(
                                    &mut nic,
                                    ip_hdr.clone(),
                                    tcp_hdr.clone(),
                                    data,
                                )?;
                            }
                            std::collections::hash_map::Entry::Vacant(v) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_hdr.clone(),
                                    tcp_hdr.clone(),
                                )? {
                                    v.insert(c);
                                }
                            }
                        };
                        // println!(
                        //     "from {}:{} to {}:{}",
                        //     ip_hdr.source_addr(),
                        //     tcp_hdr.source_port(),
                        //     ip_hdr.destination_addr(),
                        //     tcp_hdr.destination_port()
                        // );
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
