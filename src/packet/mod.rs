use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;
pub mod buffer;
pub mod header;
pub mod qtype;
pub mod question;
pub mod record;
pub mod rscode;

use self::{
    buffer::BytePacketBuffer, header::DnsHeader, qtype::QueryType, question::DnsQuestion,
    record::DnsRecord,
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }
        Ok(())
    }

    // randomly pick up an A record in Addtional Section from upstream.
    pub fn pick_one_server(&self) -> Option<IpAddr> {
        self.answers
            .iter()
            .filter_map(|x| match x {
                DnsRecord::A { addr, .. } => Some(IpAddr::V4(*addr)),
                DnsRecord::AAAA { addr, .. } => Some(IpAddr::V6(*addr)),
                _ => None,
            })
            .next()
    }
    pub fn get_random_ipv4(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|x| match x {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }
    pub fn get_random_ipv6(&self) -> Option<Ipv6Addr> {
        self.answers
            .iter()
            .filter_map(|x| match x {
                DnsRecord::AAAA { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&String, &String)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain, host)),
                _ => None,
            })
            // discard servers not authoritative to the query.
            .filter(|(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<IpAddr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => {
                            Some(IpAddr::V4(*addr))
                        }
                        DnsRecord::AAAA { domain, addr, .. } if domain == host => {
                            Some(IpAddr::V6(*addr))
                        }
                        _ => None,
                    })
            })
            .next()
    }
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&String> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
