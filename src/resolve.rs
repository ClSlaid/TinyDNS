use std::net::UdpSocket;

use crate::packet::{
    buffer::BytePacketBuffer, qtype::QueryType, question::DnsQuestion, rscode::ResultCode,
    DnsPacket,
};

use anyhow::Result;
use rand::random;

// const FORWARD_SERVER: &str = "223.5.5.5"; // use Alibaba's public DNS to forward queries.
const FORWARD_SERVER: &str = "8.8.8.8"; // use Google's public DNS to forward queries.

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let server = (FORWARD_SERVER, 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = random();
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

    DnsPacket::from_buffer(&mut res_buffer)
}

pub fn query_handler(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut req = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = req.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    let mut is_form_error = true;
    while let Some(question) = req.questions.pop() {
        println!("Received query: {:?}", question);
        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rescode = result.header.rescode;

            println!("Got {} records in result.answers", result.answers.len());
            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }

            println!(
                "Got {} records in result.authorities",
                result.authorities.len()
            );
            for rec in result.authorities {
                println!("Answer: {:?}", rec);
                packet.authorities.push(rec);
            }

            println!("Got {} records in result.answers", result.resources.len());
            for rec in result.resources {
                println!("Answer: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            eprintln!("SERVFAIL happend!");
            packet.header.rescode = ResultCode::SERVFAIL;
        }
        is_form_error = false;
    }
    if is_form_error {
        println!("FORMER happend");
        packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}
