//! HTTP protocol decoder for Norx
//!
//! This module implements HTTP protocol decoding for HTTP/1.x traffic.

use crate::core::packet::{NorxPacket, Protocol};
use crate::protocols::{ProtocolData, ProtocolDecoder};
use std::borrow::Cow;
use std::collections::HashMap;
use std::{fmt, usize};

/// HTTP method types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    PATCH,
    Other(String),
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::GET => write!(f, "GET"),
            HttpMethod::POST => write!(f, "POST"),
            HttpMethod::PUT => write!(f, "PUT"),
            HttpMethod::DELETE => write!(f, "DELETE"),
            HttpMethod::HEAD => write!(f, "HEAD"),
            HttpMethod::OPTIONS => write!(f, "OPTIONS"),
            HttpMethod::CONNECT => write!(f, "CONNECT"),
            HttpMethod::TRACE => write!(f, "TRACE"),
            HttpMethod::PATCH => write!(f, "PATCH"),
            HttpMethod::Other(s) => write!(f, "{}", s),
        }
    }
}

impl ProtocolDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }
    
    fn can_decode(&self, packet: &NorxPacket) -> bool {
        // Check if this is TCP traffic
        if packet.protocol != Protocol::TCP {
            return false;
        }
        
        // Check for common HTTP ports
        let is_http_port = match (packet.src_port, packet.dst_port) {
            (Some(80), _) | (_, Some(80)) => true,   // HTTP
            (Some(8080), _) | (_, Some(8080)) => true, // Alternative HTTP
            (Some(8000), _) | (_, Some(8000)) => true, // Common development port
            (Some(3000), _) | (_, Some(3000)) => true, // Common development port
            _ => false,
        };
        
        if !is_http_port {
            return false;
        }
        
        // Check for HTTP signatures in the payload
        if let Some(payload) = packet.payload() {
            if payload.len() < 4 {
                return false;
            }
            
            // Check for HTTP request methods
            let starts_with_method = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("GET ") || 
                start.starts_with("POST") || 
                start.starts_with("PUT ") || 
                start.starts_with("HEAD") || 
                start.starts_with("DELE") || // DELETE
                start.starts_with("OPTI") || // OPTIONS
                start.starts_with("PATC") || // PATCH
                start.starts_with("TRAC") || // TRACE
                start.starts_with("CONN")    // CONNECT
            };
            
            // Check for HTTP response
            let starts_with_http = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("HTTP")
            };
            
            return starts_with_method || starts_with_http;
        }
        
        false
    }
    
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>> {
        if !self.can_decode(packet) {
            return None;
        }
        
        if let Some(payload) = packet.payload() {
            // Try to parse as request first
            if let Some(http_data) = self.parse_request(payload) {
                return Some(Box::new(http_data));
            }
            
            // If not a request, try to parse as response
            if let Some(http_data) = self.parse_response(payload) {
                return Some(Box::new(http_data));
            }
        }
        
        None
    }
}

/// HTTP message type (request or response)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessageType {
    Request,
    Response,
}

/// HTTP protocol data
#[derive(Debug, Clone)]
pub struct HttpData {
    /// Message type (request or response)
    pub message_type: HttpMessageType,
    /// HTTP method (for requests)
    pub method: Option<HttpMethod>,
    /// URI (for requests)
    pub uri: Option<String>,
    /// HTTP version
    pub version: String,
    /// Status code (for responses)
    pub status_code: Option<u16>,
    /// Status message (for responses)
    pub status_message: Option<String>,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// HTTP body
    pub body: Option<Vec<u8>>,
    /// Raw HTTP message
    pub raw: Vec<u8>,
}

impl ProtocolData for HttpData {
    fn protocol_name(&self) -> &'static str {
        "http"
    }
    
    fn get_field(&self, name: &str) -> Option<String> {
        match name {
            "method" => self.method.as_ref().map(|m| m.to_string()),
            "uri" => self.uri.clone(),
            "version" => Some(self.version.clone()),
            "status_code" => self.status_code.map(|c| c.to_string()),
            "status_message" => self.status_message.clone(),
            "content_type" => self.headers.get("Content-Type").cloned(),
            "content_length" => self.headers.get("Content-Length").cloned(),
            "host" => self.headers.get("Host").cloned(),
            "user_agent" => self.headers.get("User-Agent").cloned(),
            "referer" => self.headers.get("Referer").cloned(),
            "cookie" => self.headers.get("Cookie").cloned(),
            _ => self.headers.get(name).cloned(),
        }
    }
    
    fn field_names(&self) -> Vec<&'static str> {
        vec![
            "method", "uri", "version", "status_code", "status_message",
            "content_type", "content_length", "host", "user_agent", "referer", "cookie",
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

impl ProtocolDecoder for HttpDecoder {
    fn name(&self) -> &'static str {
        "http"
    }
    
    fn can_decode(&self, packet: &NorxPacket) -> bool {
        // Check if this is TCP traffic
        if packet.protocol != Protocol::TCP {
            return false;
        }
        
        // Check for common HTTP ports
        let is_http_port = match (packet.src_port, packet.dst_port) {
            (Some(80), _) | (_, Some(80)) => true,   // HTTP
            (Some(8080), _) | (_, Some(8080)) => true, // Alternative HTTP
            (Some(8000), _) | (_, Some(8000)) => true, // Common development port
            (Some(3000), _) | (_, Some(3000)) => true, // Common development port
            _ => false,
        };
        
        if !is_http_port {
            return false;
        }
        
        // Check for HTTP signatures in the payload
        if let Some(payload) = packet.payload() {
            if payload.len() < 4 {
                return false;
            }
            
            // Check for HTTP request methods
            let starts_with_method = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("GET ") || 
                start.starts_with("POST") || 
                start.starts_with("PUT ") || 
                start.starts_with("HEAD") || 
                start.starts_with("DELE") || // DELETE
                start.starts_with("OPTI") || // OPTIONS
                start.starts_with("PATC") || // PATCH
                start.starts_with("TRAC") || // TRACE
                start.starts_with("CONN")    // CONNECT
            };
            
            // Check for HTTP response
            let starts_with_http = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("HTTP")
            };
            
            return starts_with_method || starts_with_http;
        }
        
        false
    }
    
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>> {
        if !self.can_decode(packet) {
            return None;
        }
        
        if let Some(payload) = packet.payload() {
            // Try to parse as request first
            if let Some(http_data) = self.parse_request(payload) {
                return Some(Box::new(http_data));
            }
            
            // If not a request, try to parse as response
            if let Some(http_data) = self.parse_response(payload) {
                return Some(Box::new(http_data));
            }
        }
        
        None
    }
}

/// HTTP protocol decoder
pub struct HttpDecoder;

impl HttpDecoder {
    /// Create a new HTTP decoder
    pub fn new() -> Self {
        Self {}
    }
    
    /// Parse an HTTP request
    fn parse_request(&self, data: &[u8]) -> Option<HttpData> {
        let data_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = data_str.split("\r\n").collect();
        
        if lines.is_empty() {
            return None;
        }
        
        // Parse request line
        let request_line = lines[0];
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        
        if parts.len() < 3 {
            return None;
        }
        
        let method = match parts[0] {
            "GET" => HttpMethod::GET,
            "POST" => HttpMethod::POST,
            "PUT" => HttpMethod::PUT,
            "DELETE" => HttpMethod::DELETE,
            "HEAD" => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "CONNECT" => HttpMethod::CONNECT,
            "TRACE" => HttpMethod::TRACE,
            "PATCH" => HttpMethod::PATCH,
            other => HttpMethod::Other(other.to_string()),
        };
        
        let uri = parts[1].to_string();
        let version = parts[2].to_string();
        
        // Parse headers
        let mut headers = HashMap::new();
        let mut i = 1;
        
        while i < lines.len() && !lines[i].is_empty() {
            let line = lines[i];
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
            i += 1;
        }
        
        // Parse body
        let mut body = None;
        if i < lines.len() - 1 {
            let body_start = data_str.find("\r\n\r\n").map(|pos| pos + 4);
            if let Some(start) = body_start {
                if start < data.len() {
                    body = Some(data[start..].to_vec());
                }
            }
        }
        
        Some(HttpData {
            message_type: HttpMessageType::Request,
            method: Some(method),
            uri: Some(uri),
            version,
            status_code: None,
            status_message: None,
            headers,
            body,
            raw: data.to_vec(),
        })
    }
    
    /// Parse an HTTP response
    fn parse_response(&self, data: &[u8]) -> Option<HttpData> {
        let data_str: Cow<'_, str> = String::from_utf8_lossy(data);
        let lines: Vec<&str> = data_str.split("\r\n").collect();
        
        if lines.is_empty() {
            return None;
        }
        
        // Parse status line
        let status_line = lines[0];
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        
        if parts.len() < 3 {
            return None;
        }
        
        let version: String = parts[0].to_string();
        let status_code: Option<u16> = parts[1].parse::<u16>().ok();
        let status_message: String = parts[2..].join(" ");
        
        // Parse headers
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut i: usize = 1;
        
        while i < lines.len() && !lines[i].is_empty() {
            let line: &str = lines[i];
            if let Some(colon_pos ) = line.find(':') {
                let key: String = line[..colon_pos].trim().to_string();
                let value: String = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
            i += 1;
        }
        
        // Parse body
        let mut body: Option<Vec<u8>> = None;
        if i < lines.len() - 1 {
            let body_start: Option<usize> = data_str.find("\r\n\r\n").map(|pos| pos + 4);
            if let Some(start) = body_start {
                if start < data.len() {
                    body = Some(data[start..].to_vec());
                }
            }
        }
        
        Some(HttpData {
            message_type: HttpMessageType::Response,
            method: None,
            uri: None,
            version,
            status_code,
            status_message: Some(status_message),
            headers,
            body,
            raw: data.to_vec(),
        })
    }
}

// Remove duplicate trait implementation since it's already defined above
    fn name(&self) -> &'static str {
        "http"
    }
    
    fn can_decode(&self, packet: &NorxPacket) -> bool {
        // Check if this is TCP traffic
        if packet.protocol != Protocol::TCP {
            return false;
        }
        
        // Check for common HTTP ports
        let is_http_port = match (packet.src_port, packet.dst_port) {
            (Some(80), _) | (_, Some(80)) => true,   // HTTP
            (Some(8080), _) | (_, Some(8080)) => true, // Alternative HTTP
            (Some(8000), _) | (_, Some(8000)) => true, // Common development port
            (Some(3000), _) | (_, Some(3000)) => true, // Common development port
            _ => false,
        };
        
        if !is_http_port {
            return false;
        }
        
        // Check for HTTP signatures in the payload
        if let Some(payload) = packet.payload() {
            if payload.len() < 4 {
                return false;
            }
            
            // Check for HTTP request methods
            let starts_with_method = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("GET ") || 
                start.starts_with("POST") || 
                start.starts_with("PUT ") || 
                start.starts_with("HEAD") || 
                start.starts_with("DELE") || // DELETE
                start.starts_with("OPTI") || // OPTIONS
                start.starts_with("PATC") || // PATCH
                start.starts_with("TRAC") || // TRACE
                start.starts_with("CONN")    // CONNECT
            };
            
            // Check for HTTP response
            let starts_with_http = {
                let start = std::str::from_utf8(&payload[0..4]).unwrap_or("");
                start.starts_with("HTTP")
            };
            
            return starts_with_method || starts_with_http;
        }
        
        false
    }
    
    fn decode(&self, packet: &NorxPacket) -> Option<Box<dyn ProtocolData>> {
        if !self.can_decode(packet) {
            return None;
        }
        
        if let Some(payload) = packet.payload() {
            // Try to parse as request first
            if let Some(http_data) = self.parse_request(payload) {
                return Some(Box::new(http_data));
            }
            
            // If not a request, try to parse as response
            if let Some(http_data) = self.parse_response(payload) {
                return Some(Box::new(http_data));
            }
        }
        
        None
    }
};