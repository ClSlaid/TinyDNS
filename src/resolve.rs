use std::net::{IpAddr, UdpSocket};

use crate::packet::{
    buffer::BytePacketBuffer, qtype::QueryType, question::DnsQuestion, rscode::ResultCode,
    DnsPacket,
};

use anyhow::Result;
use rand::random;

// const FORWARD_SERVER: &str = "223.5.5.5"; // use Alibaba's public DNS to forward queries.
const ROOT_SERVER: &str = "192.5.5.241"; // f.root-server.net

fn lookup(qname: &str, qtype: QueryType, server: (IpAddr, u16)) -> Result<DnsPacket> {
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
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
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

pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut ns = ROOT_SERVER.parse().unwrap();

    loop {
        println!(
            "attempting lookup of {:?}{} with nameserver {}",
            qtype, qname, ns
        );

        let server = (ns, 53);
        let res = lookup(qname, qtype, server)?;

        if !res.answers.is_empty() && res.header.rescode == ResultCode::NOERROR {
            return Ok(res);
        }

        if res.header.rescode == ResultCode::NXDOMAIN {
            // domain not exist
            return Ok(res);
        }
        if let Some(new_ns) = res.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match res.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(res),
        };

        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.pick_one_server() {
            ns = new_ns;
        } else {
            return Ok(res);
        }
    }
}
