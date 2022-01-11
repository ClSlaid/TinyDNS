use anyhow::{anyhow, bail, Result};

const PACKET_SIZE: usize = 1024;

pub struct BytePacketBuffer {
    pub buf: [u8; PACKET_SIZE],
    pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        BytePacketBuffer {
            buf: [0; PACKET_SIZE],
            pos: 0,
        }
    }
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; PACKET_SIZE],
            pos: 0,
        }
    }

    /// Current position within buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position with specific number of steps
    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= PACKET_SIZE {
            return Err(anyhow!(
                "buffer's size is {}, but read to {}",
                PACKET_SIZE,
                self.pos
            ));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a signle byte, without changing the buffer position
    pub fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= PACKET_SIZE {
            return Err(anyhow!(
                "buffer's size is {}, but read to {}",
                PACKET_SIZE,
                pos
            ));
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= PACKET_SIZE {
            return Err(anyhow!(
                "buffer's size is {}, but read to {}",
                PACKET_SIZE,
                start + len
            ));
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, steping two steps forward
    pub fn read_u16(&mut self) -> Result<u16> {
        let byte_high = self.read()? as u16;
        let byte_low = self.read()? as u16;
        let res = (byte_high << 8) | byte_low;
        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);
        Ok(res)
    }

    /// Read 8 bytes, steping eight steps forward
    pub fn read_u64(&mut self) -> Result<u64> {
        let res = ((self.read()? as u64) << 56)
            | ((self.read()? as u64) << 48)
            | ((self.read()? as u64) << 40)
            | ((self.read()? as u64) << 32)
            | ((self.read()? as u64) << 24)
            | ((self.read()? as u64) << 16)
            | ((self.read()? as u64) << 8)
            | self.read()? as u64;
        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    pub fn read_qname(&mut self) -> Result<String> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut outstr = String::new();
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let delim = ".";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(anyhow!("Limit of {} jumps exceeded", max_jumps));
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform jump by updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xc0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed
                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                let str_buffer = self.get_range(pos, len as usize)?;
                let tag = String::from_utf8_lossy(str_buffer).to_lowercase();
                outstr.push_str(tag.as_str());
                // This may produce a "redundant" dot after the domain name queried
                // In fact, this is the formal Fully Qualified domain name.
                outstr.push_str(delim);

                // Move forward the full length of the label
                pos += len as usize
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(outstr)
    }

    /// Writes

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            bail!(
                "buffer's size is {}, but write to {}.",
                PACKET_SIZE,
                self.pos
            );
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        let high = ((val >> 8) & 0xff) as u8;
        let low = (val & 0xff) as u8;
        self.write(high)?;
        self.write(low)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xff) as u8)?;
        self.write(((val >> 16) & 0xff) as u8)?;
        self.write(((val >> 8) & 0xff) as u8)?;
        self.write((val & 0xff) as u8)?;
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                bail!("label {} exceeds 63 characters of length", label);
            }
            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}
