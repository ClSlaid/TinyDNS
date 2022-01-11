use std::net::UdpSocket;

use tiny_dns::packet::{
    buffer::BytePacketBuffer, qtype::QueryType, question::DnsQuestion, DnsPacket,
};

use anyhow::Result;

fn main() -> Result<()> {
    let qname = "cn.bing.com";
    let qtype = QueryType::A;

    let server = ("1.1.1.1", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 514;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    socket.send_to(&req_buffer.buf[0..req_buffer.pos()], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;
    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }

    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }

    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }
    Ok(())
}
