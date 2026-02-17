use nom::{
    IResult, Parser,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::{char, space0},
    combinator::recognize,
    sequence::delimited,
};

use super::{BacktraceFrame, ParseError, ParseResult};

/// Parse a backtrace line from strace -k output
/// Format: " > /path/to/binary(function+offset) [0xaddress]"
pub fn parse_backtrace_line(line: &str) -> ParseResult<BacktraceFrame> {
    let trimmed = line.trim_start();

    if !trimmed.starts_with('>') {
        return Err(ParseError::InvalidBacktrace(
            "Line doesn't start with '>'".to_string(),
        ));
    }

    let input = &trimmed[1..].trim_start();

    parse_frame(input)
        .map(|(_, frame)| frame)
        .map_err(|e| ParseError::InvalidBacktrace(format!("Failed to parse frame: {}", e)))
}

/// Parse a backtrace frame
fn parse_frame(input: &str) -> IResult<&str, BacktraceFrame> {
    // Parse binary path (everything up to '(' or '[')
    let (rest, binary) = take_until_any(&['(', '['])(input)?;

    let mut frame = BacktraceFrame {
        binary: binary.trim().to_string(),
        function: None,
        offset: None,
        address: String::new(),
        resolved: None,
    };

    // Try to parse function and offset in parentheses
    if rest.starts_with('(')
        && let Ok((rest2, (func, offset))) = parse_function_info(rest)
    {
        frame.function = Some(func);
        frame.offset = offset;

        // Parse address after function info
        if let Ok((_, addr)) = parse_address(rest2) {
            frame.address = addr;
        }

        return Ok(("", frame));
    }

    // No function info, just parse address
    if let Ok((_, addr)) = parse_address(rest) {
        frame.address = addr;
    }

    Ok(("", frame))
}

/// Parse function name and offset: (function+0x14) or (function) or (+0x14)
fn parse_function_info(input: &str) -> IResult<&str, (String, Option<String>)> {
    let (rest, content) = delimited(char('('), take_until(")"), char(')')).parse(input)?;

    // Check if there's a + for offset
    if let Some(plus_pos) = content.find('+') {
        let function = content[..plus_pos].to_string();
        let offset = content[plus_pos + 1..].to_string();

        if function.is_empty() {
            // Just offset, no function name
            Ok((rest, (String::new(), Some(offset))))
        } else {
            Ok((rest, (function, Some(offset))))
        }
    } else {
        // No offset, just function
        Ok((rest, (content.to_string(), None)))
    }
}

/// Parse address in brackets: [0x7f...]
fn parse_address(input: &str) -> IResult<&str, String> {
    let (rest, _) = space0(input)?;
    let (rest, addr) = delimited(
        char('['),
        recognize((tag("0x"), take_while1(|c: char| c.is_ascii_hexdigit()))),
        char(']'),
    )
    .parse(rest)?;

    Ok((rest, addr.to_string()))
}

/// Take input until any of the given characters
fn take_until_any<'a>(chars: &[char]) -> impl Fn(&'a str) -> IResult<&'a str, &'a str> + '_ {
    move |input: &'a str| {
        let pos = input
            .chars()
            .position(|c| chars.contains(&c))
            .unwrap_or(input.len());

        if pos == 0 {
            Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TakeUntil,
            )))
        } else {
            Ok((&input[pos..], &input[..pos]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_backtrace_with_function() {
        let line = " > /usr/lib/libc.so.6(__write+0x1e) [0x10e53e]";
        let frame = parse_backtrace_line(line).unwrap();

        assert_eq!(frame.binary, "/usr/lib/libc.so.6");
        assert_eq!(frame.function, Some("__write".to_string()));
        assert_eq!(frame.offset, Some("0x1e".to_string()));
        assert_eq!(frame.address, "0x10e53e");
    }

    #[test]
    fn test_parse_backtrace_no_function() {
        let line = " > /usr/lib/ld-linux-x86-64.so.2() [0x1eb40]";
        let frame = parse_backtrace_line(line).unwrap();

        assert_eq!(frame.binary, "/usr/lib/ld-linux-x86-64.so.2");
        assert_eq!(frame.function, Some(String::new()));
        assert_eq!(frame.address, "0x1eb40");
    }

    #[test]
    fn test_parse_backtrace_offset_only() {
        let line = " > /usr/lib/ld-linux-x86-64.so.2(+0x0) [0x40bf6]";
        let frame = parse_backtrace_line(line).unwrap();

        assert_eq!(frame.binary, "/usr/lib/ld-linux-x86-64.so.2");
        assert_eq!(frame.function, Some(String::new()));
        assert_eq!(frame.offset, Some("0x0".to_string()));
        assert_eq!(frame.address, "0x40bf6");
    }

    #[test]
    fn test_parse_backtrace_named_function() {
        let line = " > /usr/lib/ld-linux-x86-64.so.2(_dl_catch_exception+0xa6) [0x2456]";
        let frame = parse_backtrace_line(line).unwrap();

        assert_eq!(frame.binary, "/usr/lib/ld-linux-x86-64.so.2");
        assert_eq!(frame.function, Some("_dl_catch_exception".to_string()));
        assert_eq!(frame.offset, Some("0xa6".to_string()));
        assert_eq!(frame.address, "0x2456");
    }

    #[test]
    fn test_parse_executable_backtrace() {
        let line = " > /home/rodrigodd/repos/strace-tui/target/debug/examples/syscall_test(main+0x1e) [0x23dee]";
        let frame = parse_backtrace_line(line).unwrap();

        assert!(frame.binary.contains("syscall_test"));
        assert_eq!(frame.function, Some("main".to_string()));
        assert_eq!(frame.offset, Some("0x1e".to_string()));
        assert_eq!(frame.address, "0x23dee");
    }
}
