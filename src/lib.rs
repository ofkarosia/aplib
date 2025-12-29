use std::result;
use crc32fast::Hasher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AplibError {
    #[error("Out of bounds")]
    OutOfBounds,
    #[error("CRC mismatch")]
    CrcMismatch,
    #[error("Invalid offset")]
    InvalidOffset,
    #[error("Size mismatch: {0}")]
    SizeMismatch(&'static str),
    #[error("Input too short for {0}")]
    InputTooShort(&'static str)
}

struct AplibContext<'a, 'b> {
    source: &'a [u8],
    src_pos: usize,
    destination: &'b mut Vec<u8>,
    tag: u8,
    bitcount: i8,
    r0: usize,
    lwm: u8,
}

#[derive(Clone, Copy)]
enum BlockType {
    Literal,
    LargeMatch,
    ShortMatch,
    SingleByte,
}

pub type Result<T> = result::Result<T, AplibError>;

impl<'a, 'b> AplibContext<'a, 'b> {
    fn new(source: &'a [u8], destination: &'b mut Vec<u8>) -> Self {
        Self {
            source,
            src_pos: 0,
            destination,
            tag: 0,
            bitcount: 0,
            r0: usize::MAX,
            lwm: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.src_pos < self.source.len() {
            let b = self.source[self.src_pos];
            self.src_pos += 1;
            Ok(b)
        } else {
            Err(AplibError::OutOfBounds)
        }
    }

    fn get_bit(&mut self) -> Result<u8> {
        self.bitcount -= 1;
        if self.bitcount < 0 {
            self.tag = self.read_byte()?;
            self.bitcount = 7;
        }

        let bit = (self.tag >> 7) & 1;
        self.tag <<= 1;
        Ok(bit)
    }

    fn get_gamma(&mut self) -> Result<usize> {
        let mut result: usize = 1;
        
        loop {
            result = (result << 1) + (self.get_bit()? as usize);
            if self.get_bit()? == 0 {
                break Ok(result)
            }
        }
    }

    fn decode_block_type(&mut self) -> Result<BlockType> {
        // Determine block type by reading prefix bits
        // 0       -> Literal
        // 10      -> LargeMatch
        // 110     -> ShortMatch
        // 111     -> SingleByte
        if self.get_bit()? == 0 {
            return Ok(BlockType::Literal);
        }
        if self.get_bit()? == 0 {
            return Ok(BlockType::LargeMatch);
        }
        if self.get_bit()? == 0 {
            return Ok(BlockType::ShortMatch);
        }
        Ok(BlockType::SingleByte)
    }

    // Helper to copy data from the already decompressed buffer (lz history)
    fn copy_from_history(&mut self, offset: usize, length: usize) -> Result<()> {
        if offset == 0 || offset > self.destination.len() {
            return Err(AplibError::InvalidOffset);
        }

        if offset == 1 {
            let last = *self.destination.last().unwrap();
            self.destination.resize(self.destination.len() + length, last);
            return Ok(())
        }

        self.destination.reserve(length);
        let start = self.destination.len() - offset;

        if offset >= length {
            self.destination.extend_from_within(start..start + length);
        } else {
            for i in 0..length {
                self.destination.push(self.destination[start + i])
            }
        }

        Ok(())
    }

    fn process_block(&mut self) -> Result<bool> {
        let block_type = self.decode_block_type()?;
        match block_type {
            BlockType::Literal => {
                let b = self.read_byte()?;
                self.destination.push(b);
                self.lwm = 0;
            }
            BlockType::LargeMatch => {
                let mut offs = self.get_gamma()?;

                if self.lwm == 0 && offs == 2 {
                    // Rep-match
                    offs = self.r0;
                    let length = self.get_gamma()?;
                    self.copy_from_history(offs, length)?;
                } else {
                    // Normal large match
                    if self.lwm == 0 {
                        offs -= 3;
                    } else {
                        offs -= 2;
                    }

                    offs <<= 8;
                    offs += self.read_byte()? as usize;
                    let mut length = self.get_gamma()?;

                    if offs >= 32000 {
                        length += 1;
                    }
                    if offs >= 1280 {
                        length += 1;
                    }
                    if offs < 128 {
                        length += 2;
                    }

                    self.copy_from_history(offs, length)?;
                    self.r0 = offs;
                }
                self.lwm = 1;
            }
            BlockType::ShortMatch => {
                let b = self.read_byte()?;
                let mut offs = b as usize;
                let length = 2 + (offs & 1);
                offs >>= 1;

                if offs != 0 {
                    self.copy_from_history(offs, length)?;
                    self.r0 = offs;
                    self.lwm = 1;
                } else {
                    // End of stream marker
                    return Ok(true);
                }
            }
            BlockType::SingleByte => {
                // 4 bits offset
                let mut offs: usize = 0;
                for _ in 0..4 {
                    offs = (offs << 1) + (self.get_bit()? as usize);
                }

                if offs != 0 {
                    self.copy_from_history(offs, 1)?;
                } else {
                    self.destination.push(0);
                }
                self.lwm = 0;
            }
        }
        Ok(false)
    }

    fn depack(mut self) -> Result<()> {
        // first byte verbatim
        let first_byte = self.read_byte()?;
        self.destination.push(first_byte);

        while !self.process_block()? {}
        Ok(())
    }
}

fn verify_size(expect_size: u32, input: &[u8], crc: u32, error_msg: &'static str) -> Result<()> {
    if expect_size as usize != input.len() {
        return Err(AplibError::SizeMismatch(error_msg));
    }

    let mut hasher = Hasher::new();
    hasher.update(input);
    if crc != hasher.finalize() {
        return Err(AplibError::CrcMismatch);
    }

    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct AplibHeader {
    header_size: usize,
    packed_size: u32,
    packed_crc: u32,
    original_size: u32,
    original_crc: u32
}

fn read_header(input: &[u8]) -> Result<AplibHeader> {
    let header_slice = &input[4..24];

    let header = AplibHeader {
        header_size: u32::from_le_bytes(header_slice[0..4].try_into().unwrap()) as usize,
        packed_size: u32::from_le_bytes(header_slice[4..8].try_into().unwrap()),
        packed_crc: u32::from_le_bytes(header_slice[8..12].try_into().unwrap()),
        original_size: u32::from_le_bytes(header_slice[12..16].try_into().unwrap()),
        original_crc: u32::from_le_bytes(header_slice[16..20].try_into().unwrap()),
    };
    

    if input.len() < header.header_size {
        return Err(AplibError::InputTooShort("header"));
    }

    let end = header.header_size + header.packed_size as usize;
    if input.len() < end {
        return Err(AplibError::InputTooShort("packed data"));
    }
    let input = &input[header.header_size..end];

    verify_size(header.packed_crc, input, header.packed_crc, "packed size")?;
    Ok(header)
}

#[inline]
fn has_header(input: &[u8]) -> bool {
    input.starts_with(b"AP32") && input.len() > 24
}

#[inline]
fn create_vec(capacity: Option<usize>) -> Vec<u8> {
    if let Some(size) = capacity { Vec::with_capacity(size) } else { Vec::new() }
}

#[inline]
fn depack(data: &[u8], capacity: Option<usize>) -> Result<Vec<u8>> {
    let mut destination = create_vec(capacity);
    let ctx = AplibContext::new(data, &mut destination);
    ctx.depack()?;
    Ok(destination)
}

#[inline]
fn depack_to(data: &[u8], destination: &mut Vec<u8>) -> Result<()> {
    let ctx = AplibContext::new(data, destination);
    ctx.depack()
}

fn decompress_with(data: &[u8], capacity: Option<usize>) -> Result<Vec<u8>> {
    if !has_header(data) {
        return depack(data, capacity)
    }

    let header = read_header(data)?;
    let end = header.header_size + header.packed_size as usize;
    let dst = depack(&data[header.header_size..end], capacity)?;
    verify_size(header.original_size, &dst, header.original_crc, "original size")?;
    Ok(dst)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_with(data, None)
}

pub fn decompress_with_capacity(data: &[u8], capacity: usize) -> Result<Vec<u8>> {
    decompress_with(data, Some(capacity))
}

pub fn decompress_exact(data: &[u8], size: usize) -> Result<Vec<u8>> {
    let decompressed = decompress_with_capacity(data, size)?;
    if decompressed.len() != size {
        return Err(AplibError::SizeMismatch("decompressed size"))
    }

    Ok(decompressed)
}

pub fn decompress_to(data: &[u8], destination: &mut Vec<u8>) -> Result<()> {
    if !has_header(data) {
        return depack_to(data, destination)
    }

    let header = read_header(data)?;
    let end = header.header_size + header.packed_size as usize;
    depack_to(&data[header.header_size..end], destination)?;
    verify_size(header.original_size, &destination, header.original_crc, "original size")
}

#[cfg(test)]
mod tests {
    use super::decompress;

    #[test]
    fn test_decompress() {
        let data =
            b"T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00";
        let expected = b"The quick brown fox jumps over the lazy dog";
        let result = decompress(data).unwrap();
        assert_eq!(result, expected);
    }
}
