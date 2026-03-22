/// PKLite decompression engine.
///
/// Ported from depklite by hackerb9 (MIT license), which derives from
/// refkleen/OpenTESArena by NY00123/afritz1. The format is documented by
/// dozayon at:
/// https://github.com/afritz1/OpenTESArena/blob/master/docs/pklite_specification.md

use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PkliteError {
    Io(std::io::Error),
    NotMzExe,
    NotPklite,
    DecompressionFailed(String),
    InvalidFormat(String),
}

impl fmt::Display for PkliteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkliteError::Io(e) => write!(f, "I/O error: {e}"),
            PkliteError::NotMzExe => write!(f, "Not a valid DOS MZ executable"),
            PkliteError::NotPklite => write!(f, "File is not compressed with PKLite"),
            PkliteError::DecompressionFailed(msg) => write!(f, "Decompression failed: {msg}"),
            PkliteError::InvalidFormat(msg) => write!(f, "Invalid format: {msg}"),
        }
    }
}

impl From<std::io::Error> for PkliteError {
    fn from(e: std::io::Error) -> Self { PkliteError::Io(e) }
}

// ---------------------------------------------------------------------------
// MZ header
// ---------------------------------------------------------------------------

fn ru16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[derive(Debug, Clone)]
pub struct MzHeader {
    pub signature: u16,
    pub last_page_size: u16,
    pub num_pages: u16,
    pub num_relocs: u16,
    pub header_paragraphs: u16,
    pub min_alloc: u16,
    pub max_alloc: u16,
    pub initial_ss: u16,
    pub initial_sp: u16,
    pub checksum: u16,
    pub initial_ip: u16,
    pub initial_cs: u16,
    pub reloc_offset: u16,
    pub overlay_number: u16,
}

impl MzHeader {
    pub fn read(d: &[u8]) -> Result<Self, PkliteError> {
        if d.len() < 28 { return Err(PkliteError::NotMzExe); }
        let sig = ru16(d, 0);
        if sig != 0x5A4D && sig != 0x4D5A { return Err(PkliteError::NotMzExe); }
        Ok(MzHeader {
            signature: sig,
            last_page_size: ru16(d, 2), num_pages: ru16(d, 4),
            num_relocs: ru16(d, 6), header_paragraphs: ru16(d, 8),
            min_alloc: ru16(d, 0xA), max_alloc: ru16(d, 0xC),
            initial_ss: ru16(d, 0xE), initial_sp: ru16(d, 0x10),
            checksum: ru16(d, 0x12), initial_ip: ru16(d, 0x14),
            initial_cs: ru16(d, 0x16), reloc_offset: ru16(d, 0x18),
            overlay_number: ru16(d, 0x1A),
        })
    }

    pub fn write(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        for v in [
            self.signature, self.last_page_size, self.num_pages, self.num_relocs,
            self.header_paragraphs, self.min_alloc, self.max_alloc, self.initial_ss,
            self.initial_sp, self.checksum, self.initial_ip, self.initial_cs,
            self.reloc_offset, self.overlay_number,
        ] { b.extend_from_slice(&v.to_le_bytes()); }
        b
    }

    pub fn exe_data_size(&self) -> usize {
        let p = self.num_pages as usize;
        let l = self.last_page_size as usize;
        if p == 0 { 0 } else if l == 0 { p * 512 } else { (p - 1) * 512 + l }
    }

    pub fn code_start(&self) -> usize { self.header_paragraphs as usize * 16 }
}

// ---------------------------------------------------------------------------
// PKLite info / detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PkliteInfo {
    pub version_major: u8,
    pub version_minor: u8,
    pub extra_compression: bool,
    pub large_compression: bool,
    pub copyright: String,
    pub outer_header: MzHeader,
}

impl fmt::Display for PkliteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKLite v{}.{:02}{}{} — \"{}\"",
            self.version_major, self.version_minor,
            if self.extra_compression { " (extra)" } else { "" },
            if self.large_compression { " (large)" } else { "" },
            self.copyright.trim())
    }
}

pub fn detect_pklite(data: &[u8]) -> Result<PkliteInfo, PkliteError> {
    let header = MzHeader::read(data)?;
    if data.len() < 0x1E { return Err(PkliteError::NotPklite); }

    let ver_minor = data[0x1C] & 0x0F;
    let ver_major = data[0x1D] & 0x0F;
    let extra = (data[0x1D] & 0x10) != 0;
    let large = (data[0x1D] & 0x20) != 0;

    if ver_major == 0 || ver_major > 2 { return Err(PkliteError::NotPklite); }

    let end = std::cmp::min(data.len(), 0x1E + 60);
    let raw = String::from_utf8_lossy(&data[0x1E..end]).to_string();
    let has_sig = raw.to_uppercase().contains("PKLITE");
    let typical = header.initial_ip == 0x0100 && header.initial_cs == 0xFFF0;

    if !has_sig && !typical { return Err(PkliteError::NotPklite); }

    let copyright = raw.split('\0').next().unwrap_or("").to_string();

    Ok(PkliteInfo {
        version_major: ver_major, version_minor: ver_minor,
        extra_compression: extra, large_compression: large,
        copyright, outer_header: header,
    })
}

// ---------------------------------------------------------------------------
// Binary tree node — ported directly from depklite.c
// ---------------------------------------------------------------------------

struct Node { left: i32, right: i32, value: i32 }

const fn st(l: i32, r: i32) -> Node { Node { left: l, right: r, value: -1 } }
const fn lf(v: i32) -> Node { Node { left: 0, right: 0, value: v } }

/// Length tree (section 4.3.1). Value 25 = special case.
/// Root node is "reversed" (left/right swapped in the spec illustration).
static BIT_TREE_LENGTH: &[Node] = &[
    st(4, 1),   // [0] root (reversed)
        st(1, 2),    // [1]
            lf(2),   // [2]
        lf(3),       // [3]
    st(1, 6),    // [4]
        st(1, 2),    // [5]
            lf(4),   // [6]
        st(1, 2),    // [7]
            lf(5),   // [8]
        lf(6),       // [9]
    st(1, 6),    // [10]
        st(1, 2),    // [11]
            lf(7),   // [12]
        st(1, 2),    // [13]
            lf(8),   // [14]
        lf(9),       // [15]
    st(1, 6),    // [16]
        st(1, 2),    // [17]
            lf(10),  // [18]
        st(1, 2),    // [19]
            lf(11),  // [20]
        lf(12),      // [21]
    st(1, 6),    // [22]
        st(1, 2),    // [23]
            lf(25),  // [24]  ← special marker
        st(1, 2),    // [25]
            lf(13),  // [26]
        lf(14),      // [27]
    st(1, 6),    // [28]
        st(1, 2),    // [29]
            lf(15),  // [30]
        st(1, 2),    // [31]
            lf(16),  // [32]
        lf(17),      // [33]
    st(1, 6),    // [34]
        st(1, 2),    // [35]
            lf(18),  // [36]
        st(1, 2),    // [37]
            lf(19),  // [38]
        lf(20),      // [39]
    st(1, 4),    // [40]
        st(1, 2),    // [41]
            lf(21),  // [42]
        lf(22),      // [43]
    st(1, 2),    // [44]
        lf(23),      // [45]
    lf(24),          // [46]
];

/// Offset high-byte tree (section 4.3.2).
/// Root node is also "reversed".
static BIT_TREE_OFFSET: &[Node] = &[
    st(2, 1),    // [0] root (reversed)
        lf(0),   // [1]
    st(1, 12),   // [2]
        st(1, 4),    // [3]
            st(1, 2),    // [4]
                lf(1),   // [5]
            lf(2),       // [6]
        st(1, 4),    // [7]
            st(1, 2),    // [8]
                lf(3),   // [9]
            lf(4),       // [10]
        st(1, 2),    // [11]
            lf(5),   // [12]
        lf(6),       // [13]
    st(1, 18),   // [14]
        st(1, 8),    // [15]
            st(1, 4),    // [16]
                st(1, 2),    // [17]
                    lf(7),   // [18]
                lf(8),       // [19]
            st(1, 2),    // [20]
                lf(9),   // [21]
            lf(10),      // [22]
        st(1, 4),    // [23]
            st(1, 2),    // [24]
                lf(11),  // [25]
            lf(12),      // [26]
        st(1, 2),    // [27]
            lf(13),  // [28]
        st(1, 2),    // [29]
            lf(14),  // [30]
        lf(15),      // [31]
    st(1, 16),   // [32]
        st(1, 8),    // [33]
            st(1, 4),    // [34]
                st(1, 2),    // [35]
                    lf(16),  // [36]
                lf(17),      // [37]
            st(1, 2),    // [38]
                lf(18),  // [39]
            lf(19),      // [40]
        st(1, 4),    // [41]
            st(1, 2),    // [42]
                lf(20),  // [43]
            lf(21),      // [44]
        st(1, 2),    // [45]
            lf(22),  // [46]
        lf(23),      // [47]
    st(1, 8),    // [48]
        st(1, 4),    // [49]
            st(1, 2),    // [50]
                lf(24),  // [51]
            lf(25),      // [52]
        st(1, 2),    // [53]
            lf(26),  // [54]
        lf(27),      // [55]
    st(1, 4),    // [56]
        st(1, 2),    // [57]
            lf(28),  // [58]
        lf(29),      // [59]
    st(1, 2),    // [60]
        lf(30),  // [61]
    lf(31),          // [62]
];

// ---------------------------------------------------------------------------
// Bitstream reader — matches depklite.c exactly
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    byte_index: usize,
    bit_array: u16,
    bits_read: u8,   // 0..15 — how many bits consumed from current 16-bit word
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let bit_array = if data.len() >= 2 {
            (data[0] as u16) | ((data[1] as u16) << 8)
        } else { 0 };
        BitReader { data, byte_index: 2, bit_array, bits_read: 0 }
    }

    fn get_next_byte(&mut self) -> u8 {
        if self.byte_index < self.data.len() {
            let b = self.data[self.byte_index];
            self.byte_index += 1;
            b
        } else { 0 }
    }

    fn get_next_bit(&mut self) -> bool {
        let bit = (self.bit_array & (1 << self.bits_read)) != 0;
        self.bits_read += 1;
        if self.bits_read == 16 {
            self.bits_read = 0;
            let b1 = self.get_next_byte();
            let b2 = self.get_next_byte();
            self.bit_array = (b1 as u16) | ((b2 as u16) << 8);
        }
        bit
    }

    /// Walk a binary tree to decode a value.
    fn tree_get(&mut self, tree: &[Node]) -> i32 {
        let mut idx: usize = 0;
        loop {
            let bit = self.get_next_bit();
            if bit {
                assert!(tree[idx].right != 0, "No right branch");
                idx = (idx as i32 + tree[idx].right) as usize;
            } else {
                assert!(tree[idx].left != 0, "No left branch");
                idx = (idx as i32 + tree[idx].left) as usize;
            }
            if tree[idx].left == 0 && tree[idx].right == 0 {
                return tree[idx].value;
            }
        }
    }

    fn at_end(&self) -> bool {
        self.byte_index >= self.data.len()
    }
}

// ---------------------------------------------------------------------------
// Core decompression — faithful port of depklite_unpack()
// ---------------------------------------------------------------------------

/// Decompress raw PKLite compressed data.
/// `compressed` is the data starting from the compressed data offset.
/// `use_decryption` enables XOR decryption of literal bytes.
/// Returns the decompressed bytes.
pub fn depklite_unpack(compressed: &[u8], use_decryption: bool) -> Vec<u8> {
    let mut reader = BitReader::new(compressed);
    let mut output: Vec<u8> = Vec::with_capacity(4 * 1024 * 1024);
    let max_size = 4 * 1024 * 1024;

    loop {
        if reader.at_end() || output.len() >= max_size { break; }

        if reader.get_next_bit() {
            // --- Duplication mode ---
            let copy = reader.tree_get(BIT_TREE_LENGTH);

            let copy_count: usize;

            if copy == 25 {
                // Special case (011100 in the bit stream).
                let encrypted_byte = reader.get_next_byte();
                if encrypted_byte == 0xFE {
                    continue; // skip
                } else if encrypted_byte == 0xFF {
                    break; // done
                } else {
                    copy_count = encrypted_byte as usize + 25;
                }
            } else {
                copy_count = copy as usize;
            }

            // Decode the offset.
            let most_sig_byte: u8 = if copy_count != 2 {
                reader.tree_get(BIT_TREE_OFFSET) as u8
            } else {
                0
            };
            let least_sig_byte = reader.get_next_byte();
            let offset = (least_sig_byte as usize) | ((most_sig_byte as usize) << 8);

            // Duplicate from earlier in the output.
            let dup_start = output.len().wrapping_sub(offset);
            for i in 0..copy_count {
                let src = dup_start.wrapping_add(i);
                let byte = if src < output.len() { output[src] } else { 0 };
                output.push(byte);
            }
        } else {
            // --- Literal / Decryption mode ---
            let raw_byte = reader.get_next_byte();
            if use_decryption {
                let key = 16u8.wrapping_sub(reader.bits_read);
                output.push(raw_byte ^ key);
            } else {
                output.push(raw_byte);
            }
        }
    }

    output
}

// ---------------------------------------------------------------------------
// High-level: detect + find offset + decompress + reconstruct EXE
// ---------------------------------------------------------------------------

pub struct DecompressResult {
    pub original_exe: Vec<u8>,
    pub info: PkliteInfo,
    pub log: String,
}

pub fn decompress_pklite(data: &[u8]) -> Result<DecompressResult, PkliteError> {
    let mut log = String::new();

    let info = detect_pklite(data)?;
    log.push_str(&format!("Detected: {}\n", info));
    log.push_str(&format!(
        "Outer header: {} pages, {} relocs, header={} paragraphs\n",
        info.outer_header.num_pages, info.outer_header.num_relocs,
        info.outer_header.header_paragraphs,
    ));
    log.push_str(&format!("Entry point: {:04X}:{:04X}\n",
        info.outer_header.initial_cs, info.outer_header.initial_ip));

    let code_start = info.outer_header.code_start();
    log.push_str(&format!("Code image at file offset 0x{:04X}\n", code_start));

    // Find compressed data offset using the stub hint byte.
    let hint_offset = code_start + 0x4E;
    let compressed_start = if hint_offset < data.len() {
        let para = data[hint_offset] as usize;
        let calc = code_start + para * 16;
        if calc < data.len() && calc > code_start {
            log.push_str(&format!(
                "Compressed data at 0x{:04X} (hint byte 0x{:02X} = {} paragraphs)\n",
                calc, para, para));
            calc
        } else {
            let fb = code_start + 0x100;
            log.push_str(&format!("Fallback compressed offset 0x{:04X}\n", fb));
            fb
        }
    } else {
        code_start + 0x100
    };

    if compressed_start >= data.len() {
        return Err(PkliteError::InvalidFormat("Compressed data beyond EOF".into()));
    }

    // Use decryption for "extra" compressed files (they have XOR-encrypted literals).
    let use_decryption = info.extra_compression;
    log.push_str(&format!("XOR decryption: {}\n", if use_decryption { "enabled" } else { "disabled" }));

    // Decompress.
    let compressed = &data[compressed_start..];
    let decompressed = depklite_unpack(compressed, use_decryption);
    log.push_str(&format!("Decompressed {} bytes of code\n", decompressed.len()));

    if decompressed.len() < 16 {
        log.push_str("WARNING: Output seems too small — decompression may have failed.\n");
        log.push_str("Try running the Analyze function for more details.\n");
    }

    // Read footer (last 8 bytes of EXE area).
    let exe_end = std::cmp::min(info.outer_header.exe_data_size(), data.len());
    let (footer_ip, footer_cs, footer_sp, footer_ss) = if exe_end >= 8 {
        let f = exe_end - 8;
        (ru16(data, f), ru16(data, f + 2), ru16(data, f + 4), ru16(data, f + 6))
    } else { (0, 0, 0x200, 0) };

    log.push_str(&format!(
        "Footer: entry {:04X}:{:04X}, stack {:04X}:{:04X}\n",
        footer_cs, footer_ip, footer_ss, footer_sp));

    // Build output EXE.
    let hdr_paras: u16 = 2;
    let hdr_bytes = hdr_paras as usize * 16;
    let total = hdr_bytes + decompressed.len();
    let pages = ((total + 511) / 512) as u16;
    let last = (total % 512) as u16;

    let out_hdr = MzHeader {
        signature: 0x5A4D, last_page_size: last, num_pages: pages,
        num_relocs: 0, header_paragraphs: hdr_paras,
        min_alloc: info.outer_header.min_alloc,
        max_alloc: info.outer_header.max_alloc,
        initial_ss: footer_ss, initial_sp: footer_sp,
        checksum: 0, initial_ip: footer_ip, initial_cs: footer_cs,
        reloc_offset: 0x1C, overlay_number: 0,
    };

    let mut result = out_hdr.write();
    result.resize(hdr_bytes, 0);
    result.extend_from_slice(&decompressed);

    // Fix page count.
    let fl = result.len();
    let fp = ((fl + 511) / 512) as u16;
    let ll = (fl % 512) as u16;
    result[2..4].copy_from_slice(&ll.to_le_bytes());
    result[4..6].copy_from_slice(&fp.to_le_bytes());

    log.push_str(&format!(
        "Output: {} bytes ({} code + {} header)\n",
        result.len(), decompressed.len(), hdr_bytes));
    log.push_str("Decompression complete.\n");

    Ok(DecompressResult { original_exe: result, info, log })
}

// ---------------------------------------------------------------------------
// Analysis (no decompression)
// ---------------------------------------------------------------------------

pub fn analyze_pklite(data: &[u8]) -> String {
    let mut r = String::new();
    r.push_str(&format!("File size: {} bytes\n", data.len()));

    match MzHeader::read(data) {
        Ok(h) => {
            let sig = if h.signature == 0x5A4D { "MZ" } else { "ZM" };
            r.push_str(&format!("Signature: {} (0x{:04X})\n", sig, h.signature));
            r.push_str(&format!("Pages: {} ({} bytes)\n", h.num_pages, h.exe_data_size()));
            r.push_str(&format!("Relocations: {}\n", h.num_relocs));
            r.push_str(&format!("Header: {} paras ({} bytes)\n", h.header_paragraphs, h.code_start()));
            r.push_str(&format!("SS:SP = {:04X}:{:04X}\n", h.initial_ss, h.initial_sp));
            r.push_str(&format!("CS:IP = {:04X}:{:04X}\n", h.initial_cs, h.initial_ip));
            r.push_str(&format!("Reloc table at 0x{:04X}\n\n", h.reloc_offset));
        }
        Err(e) => { r.push_str(&format!("ERROR: {}\n", e)); return r; }
    }

    match detect_pklite(data) {
        Ok(info) => {
            r.push_str(&format!("=== PKLite Detected ===\n{}\n", info));
            r.push_str(&format!("Version bytes: {:02X} {:02X}\n", data[0x1C], data[0x1D]));

            let cs = info.outer_header.code_start();
            if cs + 16 <= data.len() {
                r.push_str(&format!("Code at 0x{:04X}: ", cs));
                for i in 0..16 { r.push_str(&format!("{:02X} ", data[cs + i])); }
                r.push('\n');
            }
            let h = cs + 0x4E;
            if h < data.len() {
                r.push_str(&format!("Stub hint: 0x{:02X} -> data at 0x{:04X}\n",
                    data[h], cs + data[h] as usize * 16));
            }
            let ee = std::cmp::min(info.outer_header.exe_data_size(), data.len());
            if ee >= 8 {
                let f = ee - 8;
                r.push_str(&format!("Footer: IP={:04X} CS={:04X} SP={:04X} SS={:04X}\n",
                    ru16(data, f), ru16(data, f+2), ru16(data, f+4), ru16(data, f+6)));
            }
        }
        Err(e) => { r.push_str(&format!("Not PKLite: {}\n", e)); }
    }
    r
}
