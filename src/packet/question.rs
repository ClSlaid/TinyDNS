use super::Result;
use super::{buffer::BytePacketBuffer, qtype::QueryType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.name = buffer.read_qname()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);

        let _ = buffer.read_u16()?; // class, handel them in future versions.

        Ok(())
    }
}
