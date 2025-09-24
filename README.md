# Norx

Norx is a network intrusion detection and prevention system written in Rust, inspired by Snort3.

## Overview

Norx aims to recreate the full functionality of Snort3 with a focus on performance, modularity, and security. It provides deep packet inspection, protocol analysis, and a flexible rule engine for detecting and preventing network threats.

## Features

- Deep Packet Inspection (DPI)
- Protocol-aware traffic analysis (HTTP, DNS, TLS, SMB, etc.)
- High-performance pattern matching
- Snort-style rule engine
- Flow tracking and session reassembly
- Preprocessors for protocol/traffic analysis
- Detection plugins for threats and anomalies
- Packet decoder and normalizer
- Logging and alerting system
- Multithreading support
- Dynamic rule reloading

## Project Structure

```
src/
├── main.rs                 # Entry point
├── config/                 # Configuration handling
├── core/                   # Core engine logic
├── protocols/              # Protocol decoders
├── preprocessors/          # Traffic analyzers
├── rules/                  # Rule parsing and matching
├── utils/                  # Utilities
└── capture/                # Packet acquisition
rules/                      # Rule definitions
tests/                      # Test suite
```

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Cargo

### Building

```bash
cargo build --release
```

### Running

```bash
cargo run --release
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.