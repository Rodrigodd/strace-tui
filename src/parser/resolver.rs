use super::{BacktraceFrame, ParseResult, ResolvedLocation};
use std::collections::HashMap;

/// Resolver for converting addresses to source locations using addr2line
pub struct Addr2LineResolver {
    /// Cache of loaders per binary path
    loaders: HashMap<String, addr2line::Loader>,
    /// Cache of resolved addresses to avoid redundant lookups
    cache: HashMap<String, Option<ResolvedLocation>>,
}

impl Addr2LineResolver {
    pub fn new() -> Self {
        Self {
            loaders: HashMap::new(),
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
        let resolved = self.resolve_address(&frame.binary, &frame.address);

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

    /// Get or create a loader for the given binary
    fn get_loader(&mut self, binary: &str) -> Option<&addr2line::Loader> {
        // If already loaded, return it
        if self.loaders.contains_key(binary) {
            return self.loaders.get(binary);
        }

        // Try to load the binary
        match addr2line::Loader::new(binary) {
            Ok(loader) => {
                self.loaders.insert(binary.to_string(), loader);
                self.loaders.get(binary)
            }
            Err(_) => None,
        }
    }

    /// Resolve an address using addr2line crate
    fn resolve_address(&mut self, binary: &str, address_str: &str) -> Option<ResolvedLocation> {
        log::debug!("Resolving address {} in binary {}", address_str, binary);
        // Get or create loader for this binary
        let loader = self.get_loader(binary)?;

        // Parse address (handle 0x prefix)
        let address_str = address_str.strip_prefix("0x").unwrap_or(address_str);
        let address = u64::from_str_radix(address_str, 16).ok()?;

        // Find location
        if let Ok(Some(location)) = loader.find_location(address) {
            // Skip if file is unknown
            if location.file == Some("??") {
                return None;
            }

            return Some(ResolvedLocation {
                file: location.file?.to_string(),
                line: location.line?,
                column: location.column,
            });
        }

        None
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
