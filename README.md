# UnPKd

> *Making PKLite-compressed DOS executables heavy again since 2026.*

A cross-platform GUI tool to detect and decompress DOS executables compressed with **PKWARE's PKLite** utility, built with **Rust** and **wxDragon** (wxWidgets bindings for Rust).

## Features

- **Detect** — instantly identifies PKLite-compressed EXE/COM files and reports version info
- **Analyze** — deep inspection of the MZ header, version bytes, copyright string, decompression stub, footer, and overlay without modifying anything
- **Decompress** — reconstructs the original uncompressed executable from the LZ77+Huffman-coded data
- **Save** — writes the decompressed file with a suggested `_unpkd` suffix
- **Detailed log** — every step of detection and decompression is reported in a monospace output pane

## What is PKLite?

PKLite was an executable compression utility by PKWARE (makers of PKZIP), widely used in the DOS era (1990–2000s). It compresses DOS EXE and COM files using LZ77 with Huffman coding. The compressed files are self-extracting — they contain a small decompression stub that runs transparently when the program is executed.

Over 10% of EXE files in the Simtel DOS archive were compressed with PKLite, making it one of the most popular executable compressors of its time.

## Supported Formats

| Format | Versions | Notes |
|--------|----------|-------|
| DOS EXE | v1.00 – v2.01 | Standard and large compression |
| DOS COM | v1.00 – v1.15 | Small compression only |

### Compression Modes

- **Standard** — default compression, original header is preserved
- **Large** — larger window size for better compression
- **Extra** (`-e` flag, Pro only) — original header is omitted; detection works but header reconstruction is approximate

## Building

### Prerequisites

**All platforms:**
- Rust (latest stable): https://rustup.rs
- CMake
- C++ compiler

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libclang-dev pkg-config libgtk-3-dev \
    libpng-dev libjpeg-dev libgl1-mesa-dev libglu1-mesa-dev \
    libxkbcommon-dev libexpat1-dev libtiff-dev
```

**Windows:**
- Visual Studio Build Tools with C++ support
- Ninja: `winget install --id=Ninja-build.Ninja -e`

**macOS:**
- Xcode Command Line Tools: `xcode-select --install`

### Build & Run

```bash
cd unpkd
cargo build --release
cargo run --release
```

wxDragon automatically downloads pre-built wxWidgets libraries on first build.

## Usage

1. **Open** a file via `File → Open` or the Browse button
2. UnPKd automatically **detects** whether the file is PKLite-compressed
3. Click **Analyze** to see detailed file structure information
4. Click **Decompress** to reconstruct the original executable
5. **Save** the result via `File → Save As`

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+O | Open file |
| Ctrl+S | Save decompressed file |
| Ctrl+A | Analyze loaded file |
| Ctrl+D | Decompress loaded file |
| Alt+F4 | Exit |

## Technical Details

### PKLite EXE Format

A PKLite-compressed DOS EXE file has this structure:

```
Offset  Content
──────  ─────────────────────────────────
0x00    MZ header (28 bytes)
0x1C    Version descriptor (2 bytes: minor, major)
0x1E    Copyright string ("PKlite(tm)...")
        Relocation table (if any)
        Original header copy (non-extra mode)
hdr*16  Decompression stub (~0x100 bytes)
        Compressed code image (LZ77+Huffman)
        Compressed relocation table
        Footer (8 bytes: original IP, CS, SP, SS)
        Overlay data (if any, retained as-is)
```

### Detection Heuristics

UnPKd identifies PKLite files using multiple signals:
- Version bytes at offset 0x1C–0x1D
- Copyright string at offset 0x1E containing "PKlite"
- Entry point CS:IP = FFF0:0100 (standard) or 0000:0000 (MEGALITE)
- Tolerates "ZM" signature and modified copyright strings

### Decompression Algorithm

PKLite uses LZ77 with Huffman coding:
- Control bit 0 → literal byte (8 bits)
- Control bit 1 → back-reference (Huffman-coded offset + length)
- End-of-stream marker (offset = 0)

The relocation table uses delta encoding with segment advancement.

## Project Structure

```
unpkd/
├── Cargo.toml          # Dependencies (wxdragon)
├── README.md           # This file
└── src/
    ├── main.rs         # wxDragon GUI application
    └── pklite.rs       # PKLite detection & decompression engine
```

## License

MIT
