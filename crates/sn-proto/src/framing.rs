use std::io::{self, Read, Write};

/// Maximum allowed frame size for TCP transport.
///
/// This protects against memory DoS if a peer sends a bogus length prefix.
pub const DEFAULT_MAX_FRAME_LEN: usize = 64 * 1024;

/// Read a single length-prefixed frame.
///
/// Format: u32 big-endian length followed by that many bytes.
pub fn read_frame<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length frame",
        ));
    }
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} > {max_len}"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a single length-prefixed frame.
///
/// Format: u32 big-endian length followed by the bytes.
pub fn write_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot write empty frame",
        ));
    }

    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;

    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Helper: batch multiple frames into a single contiguous buffer suitable for a single write.
///
/// This can improve throughput by reducing syscalls.
pub fn encode_frames_to_buffer(frames: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    let mut total = 0usize;
    for f in frames {
        if f.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot encode empty frame",
            ));
        }
        total = total
            .checked_add(4)
            .and_then(|v| v.checked_add(f.len()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "batch too large"))?;
    }

    let mut out = Vec::with_capacity(total);
    for f in frames {
        let len: u32 = f
            .len()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    Ok(out)
}
