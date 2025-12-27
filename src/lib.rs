use crc32fast::Hasher;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum AplibError {
    ReadError,
    FormatError(&'static str),
    CrcError,
    SizeMismatch,
}

impl fmt::Display for AplibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AplibError::ReadError => write!(f, "Read error"),
            AplibError::FormatError(msg) => write!(f, "Format error: {}", msg),
            AplibError::CrcError => write!(f, "CRC mismatch"),
            AplibError::SizeMismatch => write!(f, "Size mismatch"),
        }
    }
}

impl Error for AplibError {}

struct AplibContext<'a> {
    source: &'a [u8],
    src_pos: usize,
    destination: Vec<u8>,
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

impl<'a> AplibContext<'a> {
    fn new(source: &'a [u8], size_hint: Option<usize>) -> Self {
        Self {
            source,
            src_pos: 0,
            destination: Vec::with_capacity(size_hint.unwrap_or_default()),
            tag: 0,
            bitcount: 0,
            r0: usize::MAX,
            lwm: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8, AplibError> {
        if self.src_pos < self.source.len() {
            let b = self.source[self.src_pos];
            self.src_pos += 1;
            Ok(b)
        } else {
            Err(AplibError::ReadError)
        }
    }

    fn get_bit(&mut self) -> Result<u8, AplibError> {
        self.bitcount -= 1;
        if self.bitcount < 0 {
            self.tag = self.read_byte()?;
            self.bitcount = 7;
        }

        let bit = (self.tag >> 7) & 1;
        self.tag <<= 1;
        Ok(bit)
    }

    fn get_gamma(&mut self) -> Result<usize, AplibError> {
        let mut result: usize = 1;
        
        loop {
            result = (result << 1) + (self.get_bit()? as usize);
            if self.get_bit()? == 0 {
                break Ok(result)
            }
        }
    }

    fn decode_block_type(&mut self) -> Result<BlockType, AplibError> {
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
    fn copy_from_history(&mut self, offset: usize, length: usize) -> Result<(), AplibError> {
        if offset == 0 || offset > self.destination.len() {
            return Err(AplibError::FormatError("Invalid offset"));
        }

        for _ in 0..length {
            let val = self.destination[self.destination.len() - offset];
            self.destination.push(val);
        }
        Ok(())
    }

    fn process_block(&mut self) -> Result<bool, AplibError> {
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

    fn depack(mut self) -> Result<Vec<u8>, AplibError> {
        // first byte verbatim
        let first_byte = self.read_byte()?;
        self.destination.push(first_byte);

        while !self.process_block()? {}
        Ok(self.destination)
    }
}

fn verify_size(expect_size: u32, input: &[u8], crc: u32) -> Result<(), AplibError> {
    if expect_size as usize != input.len() {
        return Err(AplibError::SizeMismatch);
    }

    let mut hasher = Hasher::new();
    hasher.update(input);
    if crc != hasher.finalize() {
        return Err(AplibError::CrcError);
    }

    Ok(())
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, AplibError> {
    if !data.starts_with(b"AP32") || data.len() < 24 {
        let ctx = AplibContext::new(data, None);
        return ctx.depack();
    }

    let header_slice = &data[4..24];
    let header_size = u32::from_le_bytes(header_slice[0..4].try_into().unwrap()) as usize;
    let packed_size = u32::from_le_bytes(header_slice[4..8].try_into().unwrap());
    let packed_crc = u32::from_le_bytes(header_slice[8..12].try_into().unwrap());
    let orig_size = u32::from_le_bytes(header_slice[12..16].try_into().unwrap());
    let orig_crc = u32::from_le_bytes(header_slice[16..20].try_into().unwrap());

    if data.len() < header_size {
        return Err(AplibError::FormatError("Input too short for header"));
    }

    let end = header_size + packed_size as usize;
    if data.len() < end {
        return Err(AplibError::FormatError("Input too short for packed data"));
    }
    let input = &data[header_size..end];

    verify_size(packed_size, input, packed_crc)?;

    let ctx = AplibContext::new(input, Some(orig_size as usize));
    let result = ctx.depack()?;

    verify_size(orig_size, &result, orig_crc)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompress() {
        let data =
            b"T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00";
        let expected = b"The quick brown fox jumps over the lazy dog";
        let result = decompress(data).unwrap();
        assert_eq!(result, expected);
    }
}
