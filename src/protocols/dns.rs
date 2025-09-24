//! DNS protocol decoder for Norx
//!
//! This module implements DNS protocol decoding for DNS traffic.

use crate::core::packet::{NorxPacket, Protocol};
use crate::protocols::{ProtocolData, ProtocolDecoder};
use std::collections::HashMap;
use std::fmt;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    Other(u16),
}

impl From<u16> for DnsRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => DnsRecordType::A,
            28 => DnsRecordType::AAAA,
            5 => DnsRecordType::CNAME,
            15 => DnsRecordType::MX,
            2 => DnsRecordType::NS,
            12 => DnsRecordType::PTR,
            6 => DnsRecordType::SOA,
            33 => DnsRecordType::SRV,
            16 => DnsRecordType::TXT,
            _ => DnsRecordType::Other(value),
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
            DnsRecordType::CNAME => write!(f, "CNAME"),
            DnsRecordType::MX => write!(f, "MX"),
            DnsRecordType::NS => write!(f, "NS"),
            DnsRecordType::PTR => write!(f, "PTR"),
            DnsRecordType::SOA => write!(f, "SOA"),
            DnsRecordType::SRV => write!(f, "SRV"),
            DnsRecordType::TXT => write!(f, "TXT"),
            DnsRecordType::Other(code) => write!(f, "TYPE{}", code),
        }
    }
}

/// DNS message type (query or response)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMessageType {
    Query,
    Response,
}

/// DNS query or resource record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Domain name
    pub name: String,
    /// Record type
    pub record_type: DnsRecordType,
    /// Record class (usually IN for Internet)
    pub class: u16,
    /// Time to live (for responses)
    pub ttl: Option<u32>,
    /// Record data (for responses)
    pub data: Option<Vec<u8>>,
}

/// DNS protocol data
#[derive(Debug, Clone)]
pub struct DnsData {
    /// Message type (query or response)
    pub message_type: DnsMessageType,
    /// Transaction ID
    pub transaction_id: u16,
    /// Query response flag
    pub is_response: bool,
    /// Recursion desired flag
    pub recursion_desired: bool,
    /// Recursion available flag
    pub recursion_available: bool,
    /// Authoritative answer flag
    pub authoritative_answer: bool,
    /// Truncated flag
    pub truncated: bool,
    /// Response code
    pub response_code: u8,
    /// Questions
    pub questions: Vec<DnsRecord>,
    /// Answers
    pub answers: Vec<DnsRecord>,
    /// Authority records
    pub authorities: Vec<DnsRecord>,
    /// Additional records
    pub additionals: Vec<DnsRecord>,
    /// Raw DNS message
    pub raw: Vec<u8>,
}

impl ProtocolData for DnsData {
    fn protocol_name(&self) -> &'static str {
        "dns"
    }
    
    fn get_field(&self, name: &str) -> Option<String> {
        match name {
            "transaction_id" => Some(format!("{:#x}", self.transaction_id)),
            "is_response" => Some(self.is_response.to_string()),
            "recursion_desired" => Some(self.recursion_desired.to_string()),
            "recursion_available" => Some(self.recursion_available.to_string()),
            "authoritative_answer" => Some(self.authoritative_answer.to_string()),
            "truncated" => Some(self.truncated.to_string()),
            "response_code" => Some(self.response_code.to_string()),
            "question_count" => Some(self.questions.len().to_string()),
            "answer_count" => Some(self.answers.len().to_string()),
            "authority_count" => Some(self.authorities.len().to_string()),
            "additional_count" => Some(self.additionals.len().to_string()),
            "query_name" => self.questions.first().map(|q| q.name.clone()),
            "query_type" => self.questions.first().map(|q| q.record_type.to_string()),
            _ => None,
        }
    }
    
    fn field_names(&self) -> Vec<&'static str> {
        vec![
            "transaction_id", "is_response", "recursion_desired", "recursion_available",
            "authoritative_answer", "truncated", "response_code", "question_count",
            "answer_count", "authority_count", "additional_count", "query_name", "query_type",
        ]
    }
    
    fn to_map(&self) -> HashMap<&'static str, String> {
        let mut map: HashMap<&str, String> = HashMap::new();
        
        for name in self.field_names() {
            if let Some(value) = self.get_field(name) {
                map.insert(name, value);
            }
        }
        
        map
    }
}

/// DNS protocol decoder
pub struct DnsDecoder;

impl DnsDecoder {
    /// Create a new DNS decoder
    pub fn new() -> Self {
        Self {}
    }
    
    /// Parse a DNS message
    fn parse_dns_message(&self, data: &[u8]) -> Option<DnsData> {
        if data.len() < 12 {
            return None; // DNS header is at least 12 bytes
        }
        
        // Parse DNS header
        let transaction_id: u16 = ((data[0] as u16) << 8) | (data[1] as u16);
        let flags: u16 = ((data[2] as u16) << 8) | (data[3] as u16);
        
        let is_response: bool = (flags & 0x8000) != 0;
        let opcode: u8 = ((flags >> 11) & 0xF) as u8;
        let authoritative_answer: bool = (flags & 0x0400) != 0;
        let truncated: bool = (flags & 0x0200) != 0;
        let recursion_desired: bool = (flags & 0x0100) != 0;
        let recursion_available: bool = (flags & 0x0080) != 0;
        let response_code: u8 = (flags & 0x000F) as u8;
        
        let question_count: u16 = ((data[4] as u16) << 8) | (data[5] as u16);
        let answer_count: u16 = ((data[6] as u16) << 8) | (data[7] as u16);
        let authority_count: u16 = ((data[8] as u16) << 8) | (data[9] as u16);
        let additional_count: u16 = ((data[10] as u16) << 8) | (data[11] as u16);
        
        // Simple implementation for now - just extract the first question
        // A full implementation would need to parse the entire DNS message
        let mut questions: Vec<DnsRecord> = Vec::new();
        let mut offset: usize = 12; // Start after header
        
        // Parse questions
        for _ in 0..question_count {
            if let Some((name, new_offset)) = self.parse_dns_name(data, offset) {
                offset = new_offset;
                
                if offset + 4 <= data.len() {
                    let record_type: u16 = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
                    let class: u16 = ((data[offset + 2] as u16) << 8) | (data[offset + 3] as u16);
                    
                    questions.push(DnsRecord {
                        name,
                        record_type: DnsRecordType::from(record_type),
                        class,
                        ttl: None,
                        data: None,
                    });
                    
                    offset += 4;
                }
            }
        }
        
        // For simplicity, we're not parsing answers, authorities, and additionals in this example
        // A full implementation would parse these sections as well
        
        Some(DnsData {
            message_type: if is_response { DnsMessageType::Response } else { DnsMessageType::Query },
            transaction_id,
            is_response,
            recursion_desired,
            recursion_available,
            authoritative_answer,
            truncated,
            response_code,
            questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            raw: data.to_vec(),
        })
    }
    
    /// Parse a DNS name
    fn parse_dns_name(&self, data: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut name: String = String::new();
        let mut is_first: bool = true;
        
        loop {
            if offset >= data.len() {
                return None;
            }
            
            let length = data[offset] as usize;
            
            // Check for compression pointer
            if (length & 0xC0) == 0xC0 {
                if offset + 1 >= data.len() {
                    return None;
                }
                
                let pointer: usize = (((length & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
                offset += 2;
                
                // Recursively parse the name at the pointer location
                if let Some((pointed_name, _)) = self.parse_dns_name(data, pointer) {
                    if !is_first {
                        name.push('.');
                    }
                    name.push_str(&pointed_name);
                }
                
                return Some((name, offset));
            }
            
            // End of name
            if length == 0 {
                offset += 1;
                break;
            }
            
            // Regular label
            if offset + 1 + length > data.len() {
                return None;
            }
            
            if !is_first {
                name.push('.');
            }
            
            for i in 0..length {
                name.push(data[offset + 1 + i] as char);
            }
            
            offset += length + 1;
            is_first = false;
        }
        
        Some((name, offset))
    }
}

impl ProtocolDecoder for DnsDecoder {
    fn name(&self) -> &'static str {
        "dns"
    }
    
    fn can_decode(&self, packet: &NorxPacket) -> bool {
        // Check if this is UDP traffic on port 53
        if packet.protocol != Protocol::UDP {
            return false;
        }
        
        // Check for DNS port (53)
        let is_dns_port: bool = match (packet.src_port, packet.dst_port) {
            (Some(53), _) | (_, Some(53)) => true,
            _ => false,
        };
        
        if !is_dns_port {
            return false;
        }
        
        // Check for minimum DNS message size
        if let Some(payload) = packet.payload() {
            if payload.len() >= 12 { // DNS header is 12 bytes
                return true;
            }
        }
        
        false
    }
    
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>> {
        if !self.can_decode(packet) {
            return None;
        }
        
        if let Some(payload) = packet.payload() {
            if let Some(dns_data) = self.parse_dns_message(payload) {
                return Some(Box::new(dns_data));
            }
        }
        
        None
    }
}