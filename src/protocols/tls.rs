//! TLS protocol decoder for Norx
//!
//! This module implements TLS/SSL protocol decoding for encrypted traffic.

use crate::core::packet::{NorxPacket, Protocol};
use crate::protocols::{ProtocolData, ProtocolDecoder};
use std::collections::HashMap;
use std::fmt;

/// TLS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Unknown(u8),
}

impl From<u8> for TlsRecordType {
    fn from(value: u8) -> Self {
        match value {
            20 => TlsRecordType::ChangeCipherSpec,
            21 => TlsRecordType::Alert,
            22 => TlsRecordType::Handshake,
            23 => TlsRecordType::ApplicationData,
            24 => TlsRecordType::Heartbeat,
            _ => TlsRecordType::Unknown(value),
        }
    }
}

impl fmt::Display for TlsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsRecordType::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            TlsRecordType::Alert => write!(f, "Alert"),
            TlsRecordType::Handshake => write!(f, "Handshake"),
            TlsRecordType::ApplicationData => write!(f, "ApplicationData"),
            TlsRecordType::Heartbeat => write!(f, "Heartbeat"),
            TlsRecordType::Unknown(code) => write!(f, "Unknown({})", code),
        }
    }
}

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

impl From<u8> for TlsHandshakeType {
    fn from(value: u8) -> Self {
        match value {
            0 => TlsHandshakeType::HelloRequest,
            1 => TlsHandshakeType::ClientHello,
            2 => TlsHandshakeType::ServerHello,
            11 => TlsHandshakeType::Certificate,
            12 => TlsHandshakeType::ServerKeyExchange,
            13 => TlsHandshakeType::CertificateRequest,
            14 => TlsHandshakeType::ServerHelloDone,
            15 => TlsHandshakeType::CertificateVerify,
            16 => TlsHandshakeType::ClientKeyExchange,
            20 => TlsHandshakeType::Finished,
            _ => TlsHandshakeType::Unknown(value),
        }
    }
}

impl fmt::Display for TlsHandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsHandshakeType::HelloRequest => write!(f, "HelloRequest"),
            TlsHandshakeType::ClientHello => write!(f, "ClientHello"),
            TlsHandshakeType::ServerHello => write!(f, "ServerHello"),
            TlsHandshakeType::Certificate => write!(f, "Certificate"),
            TlsHandshakeType::ServerKeyExchange => write!(f, "ServerKeyExchange"),
            TlsHandshakeType::CertificateRequest => write!(f, "CertificateRequest"),
            TlsHandshakeType::ServerHelloDone => write!(f, "ServerHelloDone"),
            TlsHandshakeType::CertificateVerify => write!(f, "CertificateVerify"),
            TlsHandshakeType::ClientKeyExchange => write!(f, "ClientKeyExchange"),
            TlsHandshakeType::Finished => write!(f, "Finished"),
            TlsHandshakeType::Unknown(code) => write!(f, "Unknown({})", code),
        }
    }
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
    Unknown(u16),
}

impl From<u16> for TlsVersion {
    fn from(value: u16) -> Self {
        match value {
            0x0300 => TlsVersion::SSLv3,
            0x0301 => TlsVersion::TLSv1_0,
            0x0302 => TlsVersion::TLSv1_1,
            0x0303 => TlsVersion::TLSv1_2,
            0x0304 => TlsVersion::TLSv1_3,
            _ => TlsVersion::Unknown(value),
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::SSLv3 => write!(f, "SSLv3"),
            TlsVersion::TLSv1_0 => write!(f, "TLSv1.0"),
            TlsVersion::TLSv1_1 => write!(f, "TLSv1.1"),
            TlsVersion::TLSv1_2 => write!(f, "TLSv1.2"),
            TlsVersion::TLSv1_3 => write!(f, "TLSv1.3"),
            TlsVersion::Unknown(code) => write!(f, "Unknown(0x{:04x})", code),
        }
    }
}

/// TLS record
#[derive(Debug, Clone)]
pub struct TlsRecord {
    /// Record type
    pub record_type: TlsRecordType,
    /// TLS version
    pub version: TlsVersion,
    /// Record length
    pub length: u16,
    /// Record data
    pub data: Vec<u8>,
}

/// TLS handshake message
#[derive(Debug, Clone)]
pub struct TlsHandshake {
    /// Handshake type
    pub handshake_type: TlsHandshakeType,
    /// Handshake length
    pub length: u32,
    /// Handshake data
    pub data: Vec<u8>,
}

/// TLS protocol data
#[derive(Debug, Clone)]
pub struct TlsData {
    /// TLS records
    pub records: Vec<TlsRecord>,
    /// Handshake messages (if present)
    pub handshakes: Vec<TlsHandshake>,
    /// Server name indication (if present in ClientHello)
    pub server_name: Option<String>,
    /// Cipher suites (if present in ClientHello/ServerHello)
    pub cipher_suites: Vec<u16>,
    /// TLS extensions (if present)
    pub extensions: Vec<u16>,
    /// Raw TLS message
    pub raw: Vec<u8>,
}

impl ProtocolData for TlsData {
    fn protocol_name(&self) -> &'static str {
        "tls"
    }
    
    fn get_field(&self, name: &str) -> Option<String> {
        match name {
            "record_count" => Some(self.records.len().to_string()),
            "handshake_count" => Some(self.handshakes.len().to_string()),
            "server_name" => self.server_name.clone(),
            "cipher_suites" => {
                if self.cipher_suites.is_empty() {
                    None
                } else {
                    Some(self.cipher_suites.iter()
                        .map(|cs| format!("0x{:04x}", cs))
                        .collect::<Vec<_>>()
                        .join(", "))
                }
            },
            "extensions" => {
                if self.extensions.is_empty() {
                    None
                } else {
                    Some(self.extensions.iter()
                        .map(|ext| format!("0x{:04x}", ext))
                        .collect::<Vec<_>>()
                        .join(", "))
                }
            },
            "version" => self.records.first().map(|r| r.version.to_string()),
            "record_types" => {
                if self.records.is_empty() {
                    None
                } else {
                    Some(self.records.iter()
                        .map(|r| r.record_type.to_string())
                        .collect::<Vec<_>>()
                        .join(", "))
                }
            },
            "handshake_types" => {
                if self.handshakes.is_empty() {
                    None
                } else {
                    Some(self.handshakes.iter()
                        .map(|h| h.handshake_type.to_string())
                        .collect::<Vec<_>>()
                        .join(", "))
                }
            },
            _ => None,
        }
    }
    
    fn field_names(&self) -> Vec<&'static str> {
        vec![
            "record_count", "handshake_count", "server_name", "cipher_suites",
            "extensions", "version", "record_types", "handshake_types",
        ]
    }
    
    fn to_map(&self) -> HashMap<&'static str, String> {
        let mut map = HashMap::new();
        
        for name in self.field_names() {
            if let Some(value) = self.get_field(name) {
                map.insert(name, value);
            }
        }
        
        map
    }
}

/// TLS protocol decoder
pub struct TlsDecoder;

impl TlsDecoder {
    /// Create a new TLS decoder
    pub fn new() -> Self {
        Self {}
    }
    
    /// Parse a TLS message
    fn parse_tls_message(&self, data: &[u8]) -> Option<TlsData> {
        if data.len() < 5 {
            return None; // TLS record header is at least 5 bytes
        }
        
        let mut records = Vec::new();
        let mut handshakes = Vec::new();
        let mut server_name = None;
        let mut cipher_suites = Vec::new();
        let mut extensions = Vec::new();
        
        let mut offset = 0;
        
        // Parse TLS records
        while offset + 5 <= data.len() {
            let record_type = data[offset];
            let version = ((data[offset + 1] as u16) << 8) | (data[offset + 2] as u16);
            let length = ((data[offset + 3] as u16) << 8) | (data[offset + 4] as u16);
            
            if offset + 5 + length as usize > data.len() {
                break; // Incomplete record
            }
            
            let record_data = data[offset + 5..offset + 5 + length as usize].to_vec();
            
            let record = TlsRecord {
                record_type: TlsRecordType::from(record_type),
                version: TlsVersion::from(version),
                length,
                data: record_data.clone(),
            };
            
            records.push(record);
            
            // Parse handshake messages if this is a handshake record
            if record_type == 22 { // Handshake
                let mut handshake_offset = 0;
                
                while handshake_offset + 4 <= record_data.len() {
                    let handshake_type = record_data[handshake_offset];
                    let handshake_length = ((record_data[handshake_offset + 1] as u32) << 16) |
                                          ((record_data[handshake_offset + 2] as u32) << 8) |
                                          (record_data[handshake_offset + 3] as u32);
                    
                    if handshake_offset + 4 + handshake_length as usize > record_data.len() {
                        break; // Incomplete handshake message
                    }
                    
                    let handshake_data = record_data[handshake_offset + 4..handshake_offset + 4 + handshake_length as usize].to_vec();
                    
                    let handshake = TlsHandshake {
                        handshake_type: TlsHandshakeType::from(handshake_type),
                        length: handshake_length,
                        data: handshake_data.clone(),
                    };
                    
                    handshakes.push(handshake);
                    
                    // Extract information from ClientHello
                    if handshake_type == 1 { // ClientHello
                        // Extract SNI if present
                        if let Some(sni) = self.extract_sni(&handshake_data) {
                            server_name = Some(sni);
                        }
                        
                        // Extract cipher suites
                        if let Some(cs) = self.extract_cipher_suites(&handshake_data) {
                            cipher_suites = cs;
                        }
                        
                        // Extract extensions
                        if let Some(exts) = self.extract_extensions(&handshake_data) {
                            extensions = exts;
                        }
                    }
                    
                    handshake_offset += 4 + handshake_length as usize;
                }
            }
            
            offset += 5 + length as usize;
        }
        
        if records.is_empty() {
            return None;
        }
        
        Some(TlsData {
            records,
            handshakes,
            server_name,
            cipher_suites,
            extensions,
            raw: data.to_vec(),
        })
    }
    
    /// Extract Server Name Indication (SNI) from ClientHello
    fn extract_sni(&self, data: &[u8]) -> Option<String> {
        // This is a simplified implementation
        // A full implementation would need to parse the ClientHello more carefully
        
        // Look for the SNI extension (type 0x0000)
        let mut offset = 34; // Skip version, random, session ID length
        
        if offset >= data.len() {
            return None;
        }
        
        // Skip session ID
        let session_id_length: usize = data[offset] as usize;
        offset += 1 + session_id_length;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Skip cipher suites
        let cipher_suites_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2 + cipher_suites_length;
        
        if offset + 1 >= data.len() {
            return None;
        }
        
        // Skip compression methods
        let compression_methods_length: usize = data[offset] as usize;
        offset += 1 + compression_methods_length;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Extensions length
        let extensions_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;
        
        if offset + extensions_length > data.len() {
            return None;
        }
        
        // Parse extensions
        let extensions_end: usize = offset + extensions_length;
        while offset + 4 <= extensions_end {
            let extension_type: u16 = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            let extension_length: usize = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
            offset += 4;
            
            if offset + extension_length > extensions_end {
                break;
            }
            
            // Server Name Indication extension
            if extension_type == 0x0000 {
                if extension_length < 2 {
                    offset += extension_length;
                    continue;
                }
                
                let sni_list_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
                offset += 2;
                
                if offset + sni_list_length > extensions_end || sni_list_length < 3 {
                    break;
                }
                
                let name_type: u8 = data[offset];
                let name_length: usize = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
                offset += 3;
                
                if offset + name_length > extensions_end {
                    break;
                }
                
                // Host name (type 0)
                if name_type == 0 {
                    return String::from_utf8(data[offset..offset + name_length].to_vec()).ok();
                }
                
                offset += name_length;
            } else {
                offset += extension_length;
            }
        }
        
        None
    }
    
    /// Extract cipher suites from ClientHello
    fn extract_cipher_suites(&self, data: &[u8]) -> Option<Vec<u16>> {
        if data.len() < 35 {
            return None;
        }
        
        let mut offset: usize = 34; // Skip version, random, session ID length
        
        // Skip session ID
        let session_id_length: usize = data[offset] as usize;
        offset += 1 + session_id_length;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Cipher suites
        let cipher_suites_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;
        
        if offset + cipher_suites_length > data.len() || cipher_suites_length % 2 != 0 {
            return None;
        }
        
        let mut cipher_suites: Vec<u16> = Vec::new();
        for i in 0..cipher_suites_length / 2 {
            let cipher_suite: u16 = ((data[offset + i * 2] as u16) << 8) | (data[offset + i * 2 + 1] as u16);
            cipher_suites.push(cipher_suite);
        }
        
        Some(cipher_suites)
    }
    
    /// Extract extensions from ClientHello
    fn extract_extensions(&self, data: &[u8]) -> Option<Vec<u16>> {
        let mut offset: usize = 34; // Skip version, random, session ID length
        
        if offset >= data.len() {
            return None;
        }
        
        // Skip session ID
        let session_id_length: usize = data[offset] as usize;
        offset += 1 + session_id_length;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Skip cipher suites
        let cipher_suites_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2 + cipher_suites_length;
        
        if offset + 1 >= data.len() {
            return None;
        }
        
        // Skip compression methods
        let compression_methods_length: usize = data[offset] as usize;
        offset += 1 + compression_methods_length;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Extensions length
        let extensions_length: usize = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;
        
        if offset + extensions_length > data.len() {
            return None;
        }
        
        // Parse extensions
        let mut extensions: Vec<u16> = Vec::new();
        let extensions_end: usize = offset + extensions_length;
        while offset + 4 <= extensions_end {
            let extension_type: u16 = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            let extension_length: usize = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
            
            extensions.push(extension_type);
            
            offset += 4 + extension_length;
            if offset > extensions_end {
                break;
            }
        }
        
        Some(extensions)
    }
}

impl ProtocolDecoder for TlsDecoder {
    fn name(&self) -> &'static str {
        "tls"
    }
    
    fn can_decode(&self, packet: &NorxPacket) -> bool {
        // Check if this is TCP traffic on common TLS ports
        if packet.protocol != Protocol::TCP {
            return false;
        }
        
        // Check for common TLS ports
        let is_tls_port = match (packet.src_port, packet.dst_port) {
            (Some(443), _) | (_, Some(443)) => true, // HTTPS
            (Some(465), _) | (_, Some(465)) => true, // SMTPS
            (Some(636), _) | (_, Some(636)) => true, // LDAPS
            (Some(989), _) | (_, Some(989)) => true, // FTPS data
            (Some(990), _) | (_, Some(990)) => true, // FTPS control
            (Some(993), _) | (_, Some(993)) => true, // IMAPS
            (Some(995), _) | (_, Some(995)) => true, // POP3S
            (Some(8443), _) | (_, Some(8443)) => true, // Alternative HTTPS
            _ => false,
        };
        
        if !is_tls_port {
            return false;
        }
        
        // Check for TLS signatures in the payload
        if let Some(payload) = packet.payload() {
            if payload.len() < 5 {
                return false;
            }
            
            // Check for valid TLS record type
            let record_type: u8 = payload[0];
            if record_type < 20 || record_type > 24 {
                return false;
            }
            
            // Check for valid TLS version
            let version: u16 = ((payload[1] as u16) << 8) | (payload[2] as u16);
            match version {
                0x0300 | 0x0301 | 0x0302 | 0x0303 | 0x0304 => {}, // SSL 3.0, TLS 1.0-1.3
                _ => return false,
            }
            
            // Check for valid record length
            let length: u16 = ((payload[3] as u16) << 8) | (payload[4] as u16);
            if length == 0 || payload.len() < 5 + length as usize {
                return false;
            }
            
            return true;
        }
        
        false
    }
    
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>> {
        if !self.can_decode(packet) {
            return None;
        }
        
        if let Some(payload) = packet.payload() {
            if let Some(tls_data) = self.parse_tls_message(payload) {
                return Some(Box::new(tls_data));
            }
        }
        
        None
    }
}