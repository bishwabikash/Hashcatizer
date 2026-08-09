use crate::common::{to_hex, u32_le, u64_le};

// 7-Zip archives -> hashcat -m 11600.
//
// Output grammar (matches 7z2john.pl and hashcat's 7-Zip module):
//
//   $7z$<type>$<numCyclesPower>$<saltLen>$<salt>$<ivLen>$<iv>
//       $<crc>$<dataLen>$<unpackSize>$<data>[$<crcLen>$<coderAttrs>]
//
// `type` is (preprocessor << 4) | compression, or 128 when the data had to be
// truncated to a single block for the padding attack. The trailing crcLen /
// coderAttrs pair is only present when the encrypted stream is *also*
// compressed, because hashcat then has to decompress before the CRC check.
//
// Two archive layouts are handled:
//   * `-mhe=on` — the header itself is encrypted (kEncodedHeader). The pack
//     stream *is* the encrypted header.
//   * plain     — the header is readable; the AES coder sits in a folder of
//     kMainStreamsInfo and the pack stream holds the file data.
//
// The encrypted bytes always live at `32 + packPos`, never inside the header
// descriptor that points at them.

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";
const AES256_SHA256: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
const LZMA1: &[u8] = &[0x03, 0x01, 0x01];

// Structure IDs from the 7z format specification.
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_ADDITIONAL_STREAMS: u8 = 0x03;
const K_MAIN_STREAMS: u8 = 0x04;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0a;
const K_FOLDER: u8 = 0x0b;
const K_CODERS_UNPACK_SIZE: u8 = 0x0c;
const K_NUM_UNPACK_STREAM: u8 = 0x0d;
const K_ENCODED_HEADER: u8 = 0x17;

/// 7z2john truncates to one AES block past this size and switches to type 128.
const DATA_LIMIT: u64 = 0x8000_0000;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if data.len() < 32 || !data.starts_with(SIGNATURE) {
        return None;
    }
    let next_hdr_offset = u64_le(data, 12) as usize;
    let next_hdr_size = u64_le(data, 20) as usize;

    let hdr_start = 32usize.checked_add(next_hdr_offset)?;
    let hdr_end = hdr_start.checked_add(next_hdr_size)?;
    if hdr_end > data.len() || next_hdr_size == 0 {
        return None;
    }
    let header = &data[hdr_start..hdr_end];

    let mut r = Reader::new(header);
    match r.byte()? {
        K_ENCODED_HEADER => {
            let streams = parse_streams_info(&mut r)?;
            // kEncodedHeader covers two different things: a header that is
            // *encrypted* (crack it) and one that is merely LZMA-compressed
            // (7-Zip does this for any multi-file archive). In the second case
            // the AES coder describing the file data is inside the compressed
            // blob, so it has to be inflated before anything is extractable.
            if has_aes(&streams) {
                build_hash(data, &streams).map(|h| vec![h])
            } else {
                let inner = decode_header(data, &streams)?;
                let mut ir = Reader::new(&inner);
                if ir.byte()? != K_HEADER {
                    return None;
                }
                let inner_streams = parse_main_streams(&mut ir)?;
                build_hash(data, &inner_streams).map(|h| vec![h])
            }
        }
        K_HEADER => {
            let streams = parse_main_streams(&mut r)?;
            build_hash(data, &streams).map(|h| vec![h])
        }
        _ => None,
    }
}

fn has_aes(streams: &StreamsInfo) -> bool {
    streams
        .folders
        .iter()
        .any(|f| f.coders.iter().any(|c| c.id == AES256_SHA256))
}

/// Inflate a compressed (but unencrypted) kEncodedHeader back into a plain
/// kHeader. Only LZMA1 is handled — that is what 7-Zip uses for headers.
fn decode_header(file: &[u8], streams: &StreamsInfo) -> Option<Vec<u8>> {
    let folder = streams.folders.first()?;
    let coder = folder.coders.first()?;
    if coder.id.as_slice() != LZMA1 || coder.props.len() != 5 {
        return None;
    }
    let start = 32u64.checked_add(streams.pack_pos)? as usize;
    let size = *streams.pack_sizes.first()? as usize;
    let packed = file.get(start..start.checked_add(size)?)?;
    let unpack_size = folder.unpack_size();
    if unpack_size > 1 << 28 {
        return None;
    }

    // lzma-rs reads the 5 property bytes off the front like the .lzma "alone"
    // container, but 7z stores the length out-of-band and emits no end-of-stream
    // marker, so the size is supplied here and a truncated tail is tolerated.
    let mut stream = Vec::with_capacity(5 + packed.len());
    stream.extend_from_slice(&coder.props);
    stream.extend_from_slice(packed);

    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(unpack_size)),
        allow_incomplete: true,
        memlimit: Some(1 << 28),
    };
    let mut out = Vec::with_capacity(unpack_size as usize);
    lzma_rs::lzma_decompress_with_options(&mut std::io::Cursor::new(stream), &mut out, &options)
        .ok()?;
    Some(out)
}

// ---------------------------------------------------------------------------
// Hash assembly
// ---------------------------------------------------------------------------

fn build_hash(file: &[u8], streams: &StreamsInfo) -> Option<String> {
    // Locate the folder whose coder chain contains AES-256, and work out which
    // pack streams feed it.
    let mut pack_index = 0usize;
    for folder in &streams.folders {
        let aes = folder
            .coders
            .iter()
            .position(|c| c.id == AES256_SHA256);
        let Some(aes_idx) = aes else {
            pack_index += folder.num_pack_streams;
            continue;
        };
        let aes = &folder.coders[aes_idx];

        let (num_cycles_power, salt, iv) = parse_aes_props(&aes.props)?;

        // Data offset = base + every pack stream belonging to earlier folders.
        let skipped: u64 = streams.pack_sizes.get(..pack_index)?.iter().sum();
        let start = 32u64
            .checked_add(streams.pack_pos)?
            .checked_add(skipped)? as usize;
        let size = *streams.pack_sizes.get(pack_index)? as usize;
        let blob = file.get(start..start.checked_add(size)?)?;

        // The size hashcat needs is what falls out of the *AES* coder, not the
        // folder's final output: when a compressor sits downstream, decryption
        // yields the still-compressed bytes.
        let unpack_size = folder.coder_output_size(aes_idx)?;
        let crc = folder.check_crc()?;

        // A companion compression coder means hashcat must inflate before it
        // can verify the CRC, so its attributes ride along in the hash.
        let compressor = folder
            .coders
            .iter()
            .find(|c| c.id != AES256_SHA256 && !c.id.is_empty());
        let (compression, preprocessor, attrs) = classify(compressor);

        let mut data_len = blob.len() as u64;
        let mut payload = blob;
        let mut truncated = false;

        // Only worth truncating when there is padding to attack: the encrypted
        // stream must be meaningfully longer than the plaintext it holds.
        if data_len.saturating_sub(unpack_size) > 3 && data_len > DATA_LIMIT / 2 {
            let keep = payload.len() & !0x0f;
            payload = payload.get(keep.saturating_sub(16)..keep)?;
            data_len = payload.len() as u64;
            truncated = true;
        }

        let type_field = if truncated {
            128
        } else {
            (preprocessor << 4) | compression
        };

        let mut out = format!(
            "$7z${}${}${}${}${}${}${}${}${}${}",
            type_field,
            num_cycles_power,
            salt.len(),
            to_hex(&salt),
            iv.len(),
            to_hex(&iv),
            crc,
            data_len,
            unpack_size,
            to_hex(payload)
        );
        // A compressed payload has to be inflated before the CRC means anything,
        // so hashcat is told how many decompressed bytes the checksum covers
        // plus the coder properties it needs to do the inflating.
        if !truncated && compression != 0 {
            out.push_str(&format!("${}${}", folder.check_len(), to_hex(&attrs)));
        }
        return Some(out);
    }
    None
}

/// 7z AES property blob: cycles/flags byte, optional size byte, salt, IV.
fn parse_aes_props(props: &[u8]) -> Option<(u8, Vec<u8>, Vec<u8>)> {
    let b0 = *props.first()?;
    let num_cycles_power = b0 & 0x3f;

    // Bit 7 and bit 6 each contribute one to the respective length, with the
    // remainder packed into the following byte's nibbles. Reading that second
    // byte unconditionally is the classic off-by-one here.
    let (salt_size, iv_size, mut off) = if b0 & 0xc0 != 0 {
        let b1 = *props.get(1)?;
        let salt_size = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
        let iv_size = ((b0 >> 6) & 1) as usize + (b1 & 0x0f) as usize;
        (salt_size, iv_size, 2)
    } else {
        (0, 0, 1)
    };

    let salt = props.get(off..off + salt_size)?.to_vec();
    off += salt_size;
    let iv = props.get(off..off + iv_size)?.to_vec();
    Some((num_cycles_power, salt, iv))
}

/// Map a coder id onto 7z2john's (compression, preprocessor) type nibbles.
fn classify(coder: Option<&Coder>) -> (u32, u32, Vec<u8>) {
    let Some(c) = coder else {
        return (0, 0, Vec::new());
    };
    let attrs = c.props.clone();
    match c.id.as_slice() {
        [0x03, 0x01, 0x01] => (1, 0, attrs),             // LZMA1
        [0x21] => (2, 0, attrs),                          // LZMA2
        [0x03, 0x04, 0x01] => (3, 0, attrs),              // PPMd
        [0x04, 0x02, 0x02] => (6, 0, attrs),              // BZip2
        [0x04, 0x01, 0x08] => (7, 0, attrs),              // Deflate
        [0x03, 0x03, 0x01, 0x03] => (0, 1, attrs),        // BCJ x86
        [0x03, 0x03, 0x01, 0x1b] => (0, 2, attrs),        // BCJ2
        _ => (0, 0, attrs),
    }
}

// ---------------------------------------------------------------------------
// Header structures
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
}

#[derive(Default)]
struct Folder {
    coders: Vec<Coder>,
    unpack_sizes: Vec<u64>,
    num_pack_streams: usize,
    crc: Option<u32>,
    /// Per-file sizes/CRCs when one folder packs several files together.
    substream_sizes: Vec<u64>,
    substream_crcs: Vec<Option<u32>>,
}

impl Folder {
    /// The folder's output is whichever stream no bind pair consumes; for the
    /// single-coder archives we care about that is simply the last one.
    fn unpack_size(&self) -> u64 {
        self.unpack_sizes.last().copied().unwrap_or(0)
    }

    /// Size of the stream a given coder emits. Coders are listed in order and
    /// their output streams are numbered the same way, so the index is just the
    /// running total of everything declared before it.
    fn coder_output_size(&self, coder_idx: usize) -> Option<u64> {
        let out_idx: usize = self
            .coders
            .get(..coder_idx)?
            .iter()
            .map(|c| c.num_out_streams)
            .sum();
        self.unpack_sizes.get(out_idx).copied()
    }

    /// hashcat verifies the decrypted stream against one file's checksum, so a
    /// multi-file folder is represented by its first file (as 7z2john does).
    fn check_crc(&self) -> Option<u32> {
        match self.substream_crcs.first() {
            Some(Some(crc)) => Some(*crc),
            _ => self.crc,
        }
    }

    /// How many decompressed bytes that checksum covers.
    fn check_len(&self) -> u64 {
        self.substream_sizes.first().copied().unwrap_or_else(|| self.unpack_size())
    }
}

#[derive(Default)]
struct Coder {
    id: Vec<u8>,
    props: Vec<u8>,
    num_out_streams: usize,
}

/// kHeader -> skip properties/additional streams -> kMainStreamsInfo.
fn parse_main_streams(r: &mut Reader) -> Option<StreamsInfo> {
    let mut id = r.byte()?;
    if id == K_ARCHIVE_PROPERTIES {
        loop {
            let t = r.byte()?;
            if t == K_END {
                break;
            }
            let n = r.number()? as usize;
            r.skip(n)?;
        }
        id = r.byte()?;
    }
    if id == K_ADDITIONAL_STREAMS {
        let _ = parse_streams_info(r)?;
        id = r.byte()?;
    }
    if id != K_MAIN_STREAMS {
        return None;
    }
    parse_streams_info(r)
}

fn parse_streams_info(r: &mut Reader) -> Option<StreamsInfo> {
    let mut info = StreamsInfo::default();
    let mut id = r.byte()?;

    if id == K_PACK_INFO {
        info.pack_pos = r.number()?;
        let num = r.number()? as usize;
        if num > 1 << 20 {
            return None;
        }
        loop {
            match r.byte()? {
                K_END => break,
                K_SIZE => {
                    info.pack_sizes = (0..num).map(|_| r.number()).collect::<Option<_>>()?;
                }
                K_CRC => skip_digests(r, num)?,
                _ => return None,
            }
        }
        id = r.byte()?;
    }

    if id == K_UNPACK_INFO {
        parse_unpack_info(r, &mut info)?;
        id = r.byte()?;
    }

    if id == K_SUBSTREAMS_INFO {
        parse_substreams_info(r, &mut info)?;
        id = r.byte()?;
    }

    if id != K_END {
        return None;
    }
    Some(info)
}

fn parse_unpack_info(r: &mut Reader, info: &mut StreamsInfo) -> Option<()> {
    if r.byte()? != K_FOLDER {
        return None;
    }
    let num_folders = r.number()? as usize;
    if num_folders > 1 << 20 {
        return None;
    }
    let external = r.byte()?;
    if external != 0 {
        // Folder definitions live in an additional stream we cannot resolve.
        return None;
    }
    info.folders = (0..num_folders).map(|_| parse_folder(r)).collect::<Option<_>>()?;

    if r.byte()? != K_CODERS_UNPACK_SIZE {
        return None;
    }
    for folder in info.folders.iter_mut() {
        let outs = folder.coders.iter().map(|c| c.num_out_streams).sum::<usize>();
        folder.unpack_sizes = (0..outs).map(|_| r.number()).collect::<Option<_>>()?;
    }

    loop {
        match r.byte()? {
            K_END => break,
            K_CRC => {
                let defined = read_bool_vector(r, num_folders)?;
                for (i, is_def) in defined.iter().enumerate() {
                    if *is_def {
                        info.folders.get_mut(i)?.crc = Some(r.u32()?);
                    }
                }
            }
            other => {
                if other == K_SIZE {
                    return None;
                }
                let n = r.number()? as usize;
                r.skip(n)?;
            }
        }
    }
    Some(())
}

/// kSubStreamsInfo splits each folder's single output back into the individual
/// files it contains, which is where per-file sizes and CRCs live.
fn parse_substreams_info(r: &mut Reader, info: &mut StreamsInfo) -> Option<()> {
    let mut counts: Vec<usize> = vec![1; info.folders.len()];
    let mut saw_sizes = false;

    loop {
        match r.byte()? {
            K_END => break,
            K_NUM_UNPACK_STREAM => {
                for c in counts.iter_mut() {
                    *c = r.number()? as usize;
                    if *c > 1 << 20 {
                        return None;
                    }
                }
            }
            K_SIZE => {
                saw_sizes = true;
                // Every substream but the last is listed; the last is whatever
                // remains of the folder's output.
                for (i, &count) in counts.iter().enumerate() {
                    let folder = info.folders.get_mut(i)?;
                    let total = folder.unpack_size();
                    let mut sum = 0u64;
                    for _ in 0..count.saturating_sub(1) {
                        let sz = r.number()?;
                        sum = sum.checked_add(sz)?;
                        folder.substream_sizes.push(sz);
                    }
                    if count > 0 {
                        folder.substream_sizes.push(total.checked_sub(sum)?);
                    }
                }
            }
            K_CRC => {
                // A folder holding exactly one file already has that file's CRC
                // recorded in kUnPackInfo, so it is omitted from this list.
                let unknown: usize = counts
                    .iter()
                    .enumerate()
                    .map(|(i, &c)| {
                        let known = c == 1 && info.folders.get(i).and_then(|f| f.crc).is_some();
                        if known { 0 } else { c }
                    })
                    .sum();
                let defined = read_bool_vector(r, unknown)?;
                let mut seen = 0usize;
                for (i, &c) in counts.iter().enumerate() {
                    let folder = info.folders.get_mut(i)?;
                    if c == 1 && folder.crc.is_some() {
                        folder.substream_crcs.push(folder.crc);
                        continue;
                    }
                    for _ in 0..c {
                        let crc = if *defined.get(seen)? { Some(r.u32()?) } else { None };
                        folder.substream_crcs.push(crc);
                        seen += 1;
                    }
                }
            }
            _ => return None,
        }
    }

    // With no explicit size list every folder holds exactly one file.
    if !saw_sizes {
        for (i, &count) in counts.iter().enumerate() {
            let folder = info.folders.get_mut(i)?;
            if count == 1 && folder.substream_sizes.is_empty() {
                folder.substream_sizes.push(folder.unpack_size());
            }
        }
    }
    Some(())
}

fn parse_folder(r: &mut Reader) -> Option<Folder> {
    let mut folder = Folder::default();
    let num_coders = r.number()? as usize;
    if num_coders == 0 || num_coders > 64 {
        return None;
    }

    let mut total_in = 0usize;
    let mut total_out = 0usize;
    for _ in 0..num_coders {
        let flags = r.byte()?;
        let id_size = (flags & 0x0f) as usize;
        let is_complex = flags & 0x10 != 0;
        let has_attrs = flags & 0x20 != 0;

        let id = r.take(id_size)?.to_vec();
        let (num_in, num_out) = if is_complex {
            (r.number()? as usize, r.number()? as usize)
        } else {
            (1, 1)
        };
        let props = if has_attrs {
            let n = r.number()? as usize;
            r.take(n)?.to_vec()
        } else {
            Vec::new()
        };

        total_in += num_in;
        total_out += num_out;
        folder.coders.push(Coder { id, props, num_out_streams: num_out });
    }

    // Bind pairs wire coder outputs into coder inputs; whatever is left over is
    // fed directly from the pack streams.
    let num_bind_pairs = total_out.checked_sub(1)?;
    for _ in 0..num_bind_pairs {
        let _in_index = r.number()?;
        let _out_index = r.number()?;
    }

    let num_packed = total_in.checked_sub(num_bind_pairs)?;
    if num_packed > 1 {
        for _ in 0..num_packed {
            let _index = r.number()?;
        }
    }
    folder.num_pack_streams = num_packed;
    Some(folder)
}

fn skip_digests(r: &mut Reader, count: usize) -> Option<()> {
    let defined = read_bool_vector(r, count)?;
    for d in defined {
        if d {
            r.u32()?;
        }
    }
    Some(())
}

fn read_bool_vector(r: &mut Reader, count: usize) -> Option<Vec<bool>> {
    if r.byte()? != 0 {
        return Some(vec![true; count]);
    }
    let mut out = Vec::with_capacity(count);
    let mut mask = 0u8;
    let mut byte = 0u8;
    for _ in 0..count {
        if mask == 0 {
            byte = r.byte()?;
            mask = 0x80;
        }
        out.push(byte & mask != 0);
        mask >>= 1;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Byte reader with 7z variable-length number decoding
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32_le(s, 0))
    }

    /// 7z NUMBER: a leading byte whose high bits say how many extra bytes
    /// follow, with the unused low bits contributing the high part of the value.
    fn number(&mut self) -> Option<u64> {
        let first = self.byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = (first as u64) & ((mask as u64) - 1);
                return Some(value | (high << (8 * i)));
            }
            value |= (self.byte()? as u64) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }
}
