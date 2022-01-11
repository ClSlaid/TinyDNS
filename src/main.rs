use std::fs::File;
use std::io::Read;

use tiny_dns::packet::{buffer::BytePacketBuffer, DnsPacket};

use anyhow::{Context, Result};

const RESPONSE_PATH: &'static str = "response-packet.txt";

fn main() -> Result<()> {
    let mut f = File::open(RESPONSE_PATH)
        .with_context(|| format!("Failed to read file {}", RESPONSE_PATH))?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }
    Ok(())
}
