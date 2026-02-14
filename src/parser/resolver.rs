use std::collections::HashMap;
use std::process::Command;
use super::{BacktraceFrame, ParseResult, ResolvedLocation};

/// Resolver for converting addresses to source locations using addr2line
pub struct Addr2LineResolver {
    /// Cache of resolved addresses to avoid redundant lookups
    cache: HashMap<String, Option<ResolvedLocation>>,
}

impl Addr2LineResolver {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    
    /// Get the number of cached resolutions
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
    
    /// Resolve a single backtrace frame
    pub fn resolve_frame(&mut self, frame: &mut BacktraceFrame) -> ParseResult<()> {
        let cache_key = format!("{}:{}", frame.binary, frame.address);
        
        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            frame.resolved = cached.clone();
            return Ok(());
        }
        
        // Try to resolve using addr2line
        let resolved = self.call_addr2line(&frame.binary, &frame.address)?;
        
        // Cache the result
        self.cache.insert(cache_key, resolved.clone());
        frame.resolved = resolved;
        
        Ok(())
    }
    
    /// Resolve all frames in a list
    pub fn resolve_frames(&mut self, frames: &mut [BacktraceFrame]) -> ParseResult<()> {
        for frame in frames.iter_mut() {
            // Ignore errors for individual frames
            let _ = self.resolve_frame(frame);
        }
        Ok(())
    }
    
    /// Call addr2line binary to resolve an address
    fn call_addr2line(&self, binary: &str, address: &str) -> ParseResult<Option<ResolvedLocation>> {
        // Check if addr2line is available
        let output = Command::new("addr2line")
            .arg("-e")
            .arg(binary)
            .arg("-f")  // Show function names
            .arg("-C")  // Demangle
            .arg(address)
            .output();
        
        let output = match output {
            Ok(out) => out,
            Err(_e) => {
                // addr2line not available or other error
                return Ok(None);
            }
        };
        
        if !output.status.success() {
            return Ok(None);
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        
        // addr2line output format:
        // function_name
        // file:line
        if lines.len() >= 2 {
            let location_line = lines[1];
            
            // Parse file:line or file:line:column
            if let Some((file, rest)) = location_line.split_once(':') {
                // Skip ?? which means unknown
                if file == "??" {
                    return Ok(None);
                }
                
                // Parse line number
                let line_num = if let Some((line_str, _col)) = rest.split_once(':') {
                    line_str.parse().ok()
                } else {
                    rest.parse().ok()
                };
                
                if let Some(line) = line_num {
                    return Ok(Some(ResolvedLocation {
                        file: file.to_string(),
                        line,
                        column: None,
                    }));
                }
            }
        }
        
        Ok(None)
    }
}

impl Default for Addr2LineResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::BacktraceFrame;

    #[test]
    fn test_resolver_caching() {
        let mut resolver = Addr2LineResolver::new();
        
        let mut frame = BacktraceFrame {
            binary: "/bin/echo".to_string(),
            function: Some("main".to_string()),
            offset: Some("0x10".to_string()),
            address: "0x1234".to_string(),
            resolved: None,
        };
        
        // First call - may or may not resolve depending on debug symbols
        let _ = resolver.resolve_frame(&mut frame);
        
        // Check that it's cached
        let cache_key = format!("{}:{}", frame.binary, frame.address);
        assert!(resolver.cache.contains_key(&cache_key));
    }
}
