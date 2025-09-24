//! Rules module for Norx
//!
//! This module handles rule parsing, storage, and matching.

use crate::core::flow::{Flow, FlowDirection};
use crate::core::packet::NorxPacket;
use aho_corasick::AhoCorasick;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Failed to parse rule: {0}")]
    ParseError(String),

    #[error("Invalid rule format: {0}")]
    FormatError(String),

    #[error("Failed to load rule file: {0}")]
    IoError(#[from] std::io::Error),
}

/// Rule action to take when a rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Alert on match
    Alert,
    /// Log the match
    Log,
    /// Drop the packet (in inline mode)
    Drop,
    /// Reject the packet (in inline mode)
    Reject,
    /// Pass the packet without further inspection
    Pass,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleAction::Alert => write!(f, "alert"),
            RuleAction::Log => write!(f, "log"),
            RuleAction::Drop => write!(f, "drop"),
            RuleAction::Reject => write!(f, "reject"),
            RuleAction::Pass => write!(f, "pass"),
        }
    }
}

impl TryFrom<&str> for RuleAction {
    type Error = RuleError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "alert" => Ok(RuleAction::Alert),
            "log" => Ok(RuleAction::Log),
            "drop" => Ok(RuleAction::Drop),
            "reject" => Ok(RuleAction::Reject),
            "pass" => Ok(RuleAction::Pass),
            _ => Err(RuleError::ParseError(format!("Invalid rule action: {}", s))),
        }
    }
}

/// Rule protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProtocol {
    /// IP protocol
    IP,
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
    /// ICMP protocol
    ICMP,
    /// HTTP protocol
    HTTP,
    /// DNS protocol
    DNS,
    /// TLS/SSL protocol
    TLS,
    /// SMB protocol
    SMB,
    /// Any protocol
    Any,
}

impl fmt::Display for RuleProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleProtocol::IP => write!(f, "ip"),
            RuleProtocol::TCP => write!(f, "tcp"),
            RuleProtocol::UDP => write!(f, "udp"),
            RuleProtocol::ICMP => write!(f, "icmp"),
            RuleProtocol::HTTP => write!(f, "http"),
            RuleProtocol::DNS => write!(f, "dns"),
            RuleProtocol::TLS => write!(f, "tls"),
            RuleProtocol::SMB => write!(f, "smb"),
            RuleProtocol::Any => write!(f, "any"),
        }
    }
}

impl TryFrom<&str> for RuleProtocol {
    type Error = RuleError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "ip" => Ok(RuleProtocol::IP),
            "tcp" => Ok(RuleProtocol::TCP),
            "udp" => Ok(RuleProtocol::UDP),
            "icmp" => Ok(RuleProtocol::ICMP),
            "http" => Ok(RuleProtocol::HTTP),
            "dns" => Ok(RuleProtocol::DNS),
            "tls" | "ssl" => Ok(RuleProtocol::TLS),
            "smb" => Ok(RuleProtocol::SMB),
            "any" => Ok(RuleProtocol::Any),
            _ => Err(RuleError::ParseError(format!("Invalid rule protocol: {}", s))),
        }
    }
}

/// Rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDirection {
    /// Unidirectional (source -> destination)
    Unidirectional,
    /// Bidirectional (source <-> destination)
    Bidirectional,
}

impl fmt::Display for RuleDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleDirection::Unidirectional => write!(f, "->"),
            RuleDirection::Bidirectional => write!(f, "<>"),
        }
    }
}

impl TryFrom<&str> for RuleDirection {
    type Error = RuleError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "->" => Ok(RuleDirection::Unidirectional),
            "<>" => Ok(RuleDirection::Bidirectional),
            _ => Err(RuleError::ParseError(format!("Invalid rule direction: {}", s))),
        }
    }
}

/// Rule content match
#[derive(Debug, Clone)]
pub struct RuleContent {
    /// Content pattern to match
    pub pattern: Vec<u8>,
    /// Case insensitive flag
    pub nocase: bool,
    /// Offset to start matching from
    pub offset: Option<usize>,
    /// Depth to match within
    pub depth: Option<usize>,
    /// Distance from previous match
    pub distance: Option<usize>,
    /// Within constraint from previous match
    pub within: Option<usize>,
    /// HTTP specific modifiers
    pub http_modifiers: Vec<String>,
}

/// Rule option
#[derive(Debug, Clone)]
pub enum RuleOption {
    /// Content match
    Content(RuleContent),
    /// PCRE regular expression
    Pcre(String),
    /// Flow direction
    Flow(String),
    /// Metadata
    Metadata(HashMap<String, String>),
    /// Reference
    Reference(String, String),
    /// Message
    Msg(String),
    /// Revision
    Rev(u32),
    /// Signature ID
    Sid(u32),
    /// Classification
    Classtype(String),
    /// Priority
    Priority(u32),
    /// Other option
    Other(String, Option<String>),
}

/// Rule header
#[derive(Debug, Clone)]
pub struct RuleHeader {
    /// Rule action
    pub action: RuleAction,
    /// Rule protocol
    pub protocol: RuleProtocol,
    /// Source IP address
    pub src_ip: String,
    /// Source port
    pub src_port: String,
    /// Rule direction
    pub direction: RuleDirection,
    /// Destination IP address
    pub dst_ip: String,
    /// Destination port
    pub dst_port: String,
}

/// Rule definition
#[derive(Debug, Clone)]
pub struct Rule {
    /// Rule header
    pub header: RuleHeader,
    /// Rule options
    pub options: Vec<RuleOption>,
    /// Raw rule string
    pub raw: String,
    /// Compiled pattern matcher for content options
    pub pattern_matcher: Option<AhoCorasick>,
    /// Compiled regular expressions
    pub regexes: Vec<Regex>,
}

impl Rule {
    /// Create a new rule from a rule string
    pub fn new(rule_str: &str) -> Result<Self, RuleError> {
        // TODO: Implement rule parsing
        // This is a placeholder implementation
        Err(RuleError::ParseError("Rule parsing not implemented yet".to_string()))
    }

    /// Check if the rule matches a packet
    pub fn matches(&self, packet: &NorxPacket, flow: &Arc<Mutex<Flow>>, direction: FlowDirection) -> bool {
        // TODO: Implement rule matching
        // This is a placeholder implementation
        false
    }
}

/// Rule match result
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Matched rule
    pub rule: Arc<Rule>,
    /// Matched packet
    pub packet: NorxPacket,
    /// Match timestamp
    pub timestamp: SystemTime,
    /// Flow information
    pub flow_id: Option<String>,
}

/// Rule set containing all loaded rules
pub struct RuleSet {
    /// All rules
    rules: Vec<Arc<Rule>>,
    /// Rules indexed by SID
    rules_by_sid: HashMap<u32, Arc<Rule>>,
    /// Pattern matcher for fast matching
    pattern_matcher: Option<AhoCorasick>,
    /// Patterns to rule mapping
    patterns_to_rules: HashMap<usize, Vec<Arc<Rule>>>,
}

impl RuleSet {
    /// Create a new empty rule set
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            rules_by_sid: HashMap::new(),
            pattern_matcher: None,
            patterns_to_rules: HashMap::new(),
        }
    }

    /// Load rules from a file
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, RuleError> {
        let content: String = std::fs::read_to_string(path)?;
        self.load_rules(&content)
    }

    /// Load rules from a string
    pub fn load_rules(&mut self, rules_str: &str) -> Result<usize, RuleError> {
        let mut count: usize = 0;
        
        for line in rules_str.lines() {
            let line: &str = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse rule
            match Rule::new(line) {
                Ok(rule) => {
                    // Extract SID if available
                    let sid: Option<u32> = rule.options.iter().find_map(|opt| {
                        if let RuleOption::Sid(sid) = opt {
                            Some(*sid)
                        } else {
                            None
                        }
                    });
                    
                    let rule: Arc<Rule> = Arc::new(rule);
                    
                    // Add rule to the set
                    self.rules.push(Arc::clone(&rule));
                    
                    // Index by SID if available
                    if let Some(sid) = sid {
                        self.rules_by_sid.insert(sid, Arc::clone(&rule));
                    }
                    
                    count += 1;
                },
                Err(e) => {
                    // Log error but continue parsing other rules
                    eprintln!("Error parsing rule: {}", e);
                }
            }
        }
        
        // Rebuild pattern matcher
        self.build_pattern_matcher();
        
        Ok(count)
    }

    /// Build pattern matcher for fast content matching
    fn build_pattern_matcher(&mut self) {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut patterns_to_rules: HashMap<usize, Vec<Arc<Rule>>> = HashMap::new();
        
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            for opt in &rule.options {
                if let RuleOption::Content(content) = opt {
                    let pattern_idx = patterns.len();
                    patterns.push(content.pattern.clone());
                    
                    patterns_to_rules
                        .entry(pattern_idx)
                        .or_insert_with(Vec::new)
                        .push(Arc::clone(rule));
                }
            }
        }
        
        if !patterns.is_empty() {
            self.pattern_matcher = Some(AhoCorasick::new(patterns).unwrap());
            self.patterns_to_rules = patterns_to_rules;
        }
    }

    /// Apply rules to a packet
    pub fn apply_rules(&self, packet: &NorxPacket, flow: &Arc<Mutex<Flow>>, direction: FlowDirection) -> Vec<RuleMatch> {
        let mut matches: Vec<RuleMatch> = Vec::new();
        
        // Fast pattern matching using Aho-Corasick
        if let Some(payload) = packet.payload() {
            if let Some(matcher) = &self.pattern_matcher {
                let mut matched_rules: std::collections::HashSet<String> = std::collections::HashSet::new();
                
                for mat in matcher.find_iter(payload) {
                    if let Some(rules) = self.patterns_to_rules.get(&mat.pattern()) {
                        for rule in rules {
                            // Skip rules we've already matched
                            if matched_rules.contains(&rule.raw) {
                                continue;
                            }
                            
                            // Check if the rule fully matches
                            if rule.matches(packet, flow, direction) {
                                matched_rules.insert(rule.raw.clone());
                                
                                matches.push(RuleMatch {
                                    rule: Arc::clone(rule),
                                    packet: packet.clone(),
                                    timestamp: SystemTime::now(),
                                    flow_id: Some(format!("{:?}", flow.lock().unwrap().key)),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        // Apply rules that don't have content patterns
        for rule in &self.rules {
            // Skip rules with content patterns (already checked above)
            let has_content = rule.options.iter().any(|opt| {
                matches!(opt, RuleOption::Content(_))
            });
            
            if !has_content && rule.matches(packet, flow, direction) {
                matches.push(RuleMatch {
                    rule: Arc::clone(rule),
                    packet: packet.clone(),
                    timestamp: SystemTime::now(),
                    flow_id: Some(format!("{:?}", flow.lock().unwrap().key)),
                });
            }
        }
        
        matches
    }

    /// Get a rule by SID
    pub fn get_rule_by_sid(&self, sid: u32) -> Option<Arc<Rule>> {
        self.rules_by_sid.get(&sid).cloned()
    }

    /// Get all rules
    pub fn get_all_rules(&self) -> &[Arc<Rule>] {
        &self.rules
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.rules.clear();
        self.rules_by_sid.clear();
        self.pattern_matcher = None;
        self.patterns_to_rules.clear();
    }
}