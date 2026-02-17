use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1, space0, space1},
    combinator::{opt, recognize},
    sequence::{delimited, preceded, terminated},
};

use super::{Errno, ExitInfo, ParseError, ParseResult, SignalInfo, SyscallEntry};

/// Parse a complete strace line
pub fn parse_strace_line(line: &str) -> ParseResult<SyscallEntry> {
    // Check for special lines first
    if line.contains("+++") {
        return parse_exit_line(line);
    }
    if line.contains("---") {
        return parse_signal_line(line);
    }

    // Parse regular syscall line - try different formats in order
    let (rest, (pid, timestamp)) = parse_pid_and_timestamp(line)
        .or_else(|_| parse_timestamp_only(line))
        .or_else(|_| parse_pid_only(line))
        .or_else(|_| parse_no_prefix(line))
        .map_err(|e| ParseError::InvalidFormat(format!("Failed to parse PID/timestamp: {}", e)))?;

    // Check for <... resumed> pattern
    if rest.trim_start().starts_with("<...") {
        return parse_resumed_line(pid, timestamp, rest);
    }

    // Parse syscall name and arguments
    let (rest, syscall_name) = parse_syscall_name(rest)
        .map_err(|e| ParseError::InvalidSyscall(format!("Failed to parse syscall name: {}", e)))?;

    let mut entry = SyscallEntry::new(pid, timestamp, syscall_name);

    // Parse arguments
    let (rest, args) = parse_arguments(rest)
        .map_err(|e| ParseError::InvalidSyscall(format!("Failed to parse arguments: {}", e)))?;
    entry.arguments = args;

    // Check for unfinished
    if rest.contains("<unfinished") {
        entry.is_unfinished = true;
        return Ok(entry);
    }

    // Parse return value and errno
    let (rest, return_val) = parse_return_value(rest).unwrap_or((rest, None));
    entry.return_value = return_val;

    if let Some(ref ret) = entry.return_value
        && (ret.starts_with("-1") || ret.starts_with("?"))
    {
        // Try to parse errno
        if let Ok((_, errno)) = parse_errno(rest) {
            entry.errno = Some(errno);
        }
    }

    // Parse duration
    if let Ok((_, duration)) = parse_duration(rest) {
        entry.duration = Some(duration);
    }

    Ok(entry)
}

/// Parse PID and timestamp from the start of the line
fn parse_pid_and_timestamp(input: &str) -> IResult<&str, (u32, String)> {
    let (rest, pid) = terminated(digit1, space1).parse(input)?;
    let (rest, timestamp) = terminated(parse_timestamp, space1).parse(rest)?;

    Ok((rest, (pid.parse().unwrap_or(0), timestamp.to_string())))
}

/// Parse timestamp only (no PID) - for strace without -f but with -t
fn parse_timestamp_only(input: &str) -> IResult<&str, (u32, String)> {
    let (rest, timestamp) = terminated(parse_timestamp, space1).parse(input)?;
    // Use PID 0 when no PID is present
    Ok((rest, (0, timestamp.to_string())))
}

/// Parse PID only (no timestamp) - for strace with -f but without -t
fn parse_pid_only(input: &str) -> IResult<&str, (u32, String)> {
    let (rest, pid) = terminated(digit1, space1).parse(input)?;
    // Use empty string for timestamp when no timestamp is present
    Ok((rest, (pid.parse().unwrap_or(0), String::new())))
}

/// Parse no prefix (no PID, no timestamp) - for strace without -f and without -t
fn parse_no_prefix(input: &str) -> IResult<&str, (u32, String)> {
    // Just return the input as-is with PID 0 and empty timestamp
    Ok((input, (0, String::new())))
}

/// Parse timestamp in HH:MM:SS format
fn parse_timestamp(input: &str) -> IResult<&str, &str> {
    recognize((
        digit1,
        char(':'),
        digit1,
        char(':'),
        digit1,
        opt((char('.'), digit1)),
    ))
    .parse(input)
}

/// Parse syscall name
fn parse_syscall_name(input: &str) -> IResult<&str, String> {
    let (rest, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '$')(input)?;
    Ok((rest, name.to_string()))
}

/// Parse syscall arguments (everything within parentheses)
fn parse_arguments(input: &str) -> IResult<&str, String> {
    let (rest, _) = space0(input)?;
    let (rest, _) = char('(')(rest)?;

    // Find matching closing paren, handling nested structures
    // But stop early if we see <unfinished
    let mut depth = 1;
    let mut end_pos = 0;
    let chars: Vec<char> = rest.chars().collect();
    let rest_str = rest;

    // Check if this contains <unfinished
    if rest_str.contains("<unfinished") {
        // Find where <unfinished starts and treat that as end
        if let Some(unfinished_pos) = rest_str.find("<unfinished") {
            let args: String = rest_str[..unfinished_pos]
                .trim_end_matches([',', ' '])
                .to_string();
            return Ok((rest_str.get(unfinished_pos..).unwrap_or(""), args));
        }
    }

    for (i, &c) in chars.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end_pos = i;
                    break;
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        // Unfinished or malformed
        let args: String = chars.iter().collect();
        return Ok(("", args));
    }

    let args: String = chars.iter().take(end_pos).collect();

    Ok((rest.get(end_pos + 1..).unwrap_or(""), args))
}

/// Parse return value
fn parse_return_value(input: &str) -> IResult<&str, Option<String>> {
    let (rest, _) = space0(input)?;
    let (rest, _) = char('=')(rest)?;
    let (rest, _) = space0(rest)?;

    // Return value can be a hex number, regular number, ?, or NULL
    // Order matters! Try hex first, then numbers
    let (rest, value) = alt((
        recognize((tag("0x"), take_while1(|c: char| c.is_ascii_hexdigit()))),
        recognize((opt(char('-')), digit1)),
        recognize((
            char('?'),
            opt(preceded(
                char('+'),
                take_while1(|c: char| c.is_alphanumeric() || c == '_'),
            )),
        )),
        tag("NULL"),
    ))
    .parse(rest)?;

    Ok((rest, Some(value.to_string())))
}

/// Parse errno information
fn parse_errno(input: &str) -> IResult<&str, Errno> {
    let (rest, _) = space0(input)?;
    let (rest, code) = take_while1(|c: char| c.is_uppercase() || c.is_numeric())(rest)?;

    // Try to parse message in parentheses
    let mut message = String::new();
    if let Some(start) = rest.find('(')
        && let Some(end) = rest[start..].find(')')
    {
        message = rest[start + 1..start + end].to_string();
    }

    Ok((
        rest,
        Errno {
            code: code.to_string(),
            message,
        },
    ))
}

/// Parse duration in <0.000123> format
fn parse_duration(input: &str) -> IResult<&str, f64> {
    let (rest, _) = space0(input)?;
    let (rest, duration_str) = delimited(
        char('<'),
        recognize((opt(digit1), opt((char('.'), digit1)))),
        char('>'),
    )
    .parse(rest)?;

    let duration = duration_str.parse().unwrap_or(0.0);
    Ok((rest, duration))
}

/// Parse resumed syscall line
fn parse_resumed_line(pid: u32, timestamp: String, input: &str) -> ParseResult<SyscallEntry> {
    // Examples:
    // <... syscall_name resumed> args) = retval
    // <... clone3 resumed> => {parent_tid=[7197]}, 88) = 7197
    // <... wait4 resumed>, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 24983
    let input = input.trim_start();

    // Extract syscall name
    let syscall_name = if let Some(start) = input.find("<...") {
        let after_dots = &input[start + 4..].trim_start();
        if let Some(end) = after_dots.find("resumed>") {
            after_dots[..end].trim().to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let mut entry = SyscallEntry::new(pid, timestamp, syscall_name);
    entry.is_resumed = true;

    // Try to parse arguments and return value after resumed>
    if let Some(pos) = input.find("resumed>") {
        let after_resumed = &input[pos + 8..].trim_start();

        let ret_part = if let Some(ret_start) = after_resumed.find(") = ") {
            // Everything before ") = " is the resumed arguments
            let args_part = &after_resumed[..ret_start + 1];
            entry.arguments = args_part.trim().to_string();

            Some(&after_resumed[ret_start + 1..])
        } else {
            after_resumed
                .find('=')
                .map(|eq_pos| &after_resumed[eq_pos..])
        };

        if let Some(ret_part) = ret_part
            && let Ok((rest, ret_val)) = parse_return_value(ret_part)
        {
            entry.return_value = ret_val;

            // Parse errno if present
            if let Some(ref ret) = entry.return_value
                && ret.starts_with("-1")
                && let Ok((_, errno)) = parse_errno(rest)
            {
                entry.errno = Some(errno);
            }

            // Parse duration
            if let Ok((_, duration)) = parse_duration(rest) {
                entry.duration = Some(duration);
            }
        }
    }

    Ok(entry)
}

/// Parse signal line (--- SIGNAL {...} ---)
fn parse_signal_line(line: &str) -> ParseResult<SyscallEntry> {
    let (pid, timestamp) = parse_pid_and_timestamp(line)
        .or_else(|_| parse_timestamp_only(line))
        .or_else(|_| parse_pid_only(line))
        .or_else(|_| parse_no_prefix(line))
        .map_err(|e| {
            ParseError::InvalidFormat(format!("Signal line missing PID/timestamp: {}", e))
        })?
        .1;

    let mut entry = SyscallEntry::new(pid, timestamp, "signal".to_string());

    // Extract signal info between --- and ---
    if let Some(start) = line.find("---") {
        let after_start = &line[start + 3..];
        if let Some(end) = after_start.find("---") {
            let signal_text = after_start[..end].trim();

            // Extract signal name
            let signal_name = signal_text.split_whitespace().next().unwrap_or("UNKNOWN");

            entry.signal = Some(SignalInfo {
                signal_name: signal_name.to_string(),
                details: signal_text.to_string(),
            });
        }
    }

    Ok(entry)
}

/// Parse exit line (+++ exited with N +++)
fn parse_exit_line(line: &str) -> ParseResult<SyscallEntry> {
    let (pid, timestamp) = parse_pid_and_timestamp(line)
        .or_else(|_| parse_timestamp_only(line))
        .or_else(|_| parse_pid_only(line))
        .or_else(|_| parse_no_prefix(line))
        .map_err(|e| ParseError::InvalidFormat(format!("Exit line missing PID/timestamp: {}", e)))?
        .1;

    let mut entry = SyscallEntry::new(pid, timestamp, "exit".to_string());

    // Extract exit code
    if let Some(start) = line.find("+++") {
        let after_start = &line[start + 3..];

        let exit_code = if after_start.contains("exited with") {
            // Normal exit
            after_start
                .split("with")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        } else {
            // Killed by signal
            0
        };

        entry.exit_info = Some(ExitInfo {
            code: exit_code,
            killed: after_start.contains("killed"),
        });
    }

    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_syscall() {
        let line = "12311 12:59:24 brk(NULL) = 0x5602312ea000";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 12311);
        assert_eq!(entry.timestamp, "12:59:24");
        assert_eq!(entry.syscall_name, "brk");
        assert_eq!(entry.arguments, "NULL");
        assert_eq!(entry.return_value, Some("0x5602312ea000".to_string()));
    }

    #[test]
    fn test_parse_with_errno() {
        let line = "12311 12:59:24 access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.syscall_name, "access");
        assert_eq!(entry.return_value, Some("-1".to_string()));
        assert!(entry.errno.is_some());
        let errno = entry.errno.unwrap();
        assert_eq!(errno.code, "ENOENT");
        assert_eq!(errno.message, "No such file or directory");
    }

    #[test]
    fn test_parse_unfinished() {
        let line = "12311 12:59:24 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x7fc52c21f000, stack_size=0x9000}, 88 <unfinished ...>";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.syscall_name, "clone3");
        assert!(entry.is_unfinished);
        assert!(entry.arguments.contains("CLONE_VM"));
    }

    #[test]
    fn test_parse_resumed() {
        let line = "12312 12:59:24 <... execve resumed>) = 0";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 12312);
        assert!(entry.is_resumed);
        assert_eq!(entry.syscall_name, "execve");
        assert_eq!(entry.return_value, Some("0".to_string()));
    }

    #[test]
    fn test_parse_signal() {
        let line = "12311 12:59:24 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=12312, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.syscall_name, "signal");
        assert!(entry.signal.is_some());
        let signal = entry.signal.unwrap();
        assert_eq!(signal.signal_name, "SIGCHLD");
    }

    #[test]
    fn test_parse_exit() {
        let line = "12312 12:59:24 +++ exited with 0 +++";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.syscall_name, "exit");
        assert!(entry.exit_info.is_some());
        let exit = entry.exit_info.unwrap();
        assert_eq!(exit.code, 0);
        assert!(!exit.killed);
    }

    #[test]
    fn test_parse_no_pid_simple() {
        let line = "23:14:48 brk(NULL) = 0x55772af19000";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0); // No PID = 0
        assert_eq!(entry.timestamp, "23:14:48");
        assert_eq!(entry.syscall_name, "brk");
        assert_eq!(entry.arguments, "NULL");
        assert_eq!(entry.return_value, Some("0x55772af19000".to_string()));
    }

    #[test]
    fn test_parse_no_pid_with_errno() {
        let line =
            "23:14:48 access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0);
        assert_eq!(entry.syscall_name, "access");
        assert_eq!(entry.return_value, Some("-1".to_string()));
        assert!(entry.errno.is_some());
        let errno = entry.errno.unwrap();
        assert_eq!(errno.code, "ENOENT");
    }

    #[test]
    fn test_parse_no_pid_signal() {
        let line = "23:14:48 --- SIGINT {si_signo=SIGINT, si_code=SI_USER} ---";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0);
        assert_eq!(entry.syscall_name, "signal");
        assert!(entry.signal.is_some());
        let signal = entry.signal.unwrap();
        assert_eq!(signal.signal_name, "SIGINT");
    }

    #[test]
    fn test_parse_no_pid_exit() {
        let line = "23:14:48 +++ exited with 0 +++";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0);
        assert_eq!(entry.syscall_name, "exit");
        assert!(entry.exit_info.is_some());
        let exit = entry.exit_info.unwrap();
        assert_eq!(exit.code, 0);
    }

    #[test]
    fn test_parse_pid_no_timestamp() {
        let line = "172330 execve(\"/usr/bin/sh\", [\"sh\", \"-c\", \"echo test\"], 0x7ffe /* 42 vars */) = 0";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 172330);
        assert_eq!(entry.timestamp, "");
        assert_eq!(entry.syscall_name, "execve");
        assert_eq!(entry.return_value, Some("0".to_string()));
    }

    #[test]
    fn test_parse_no_pid_no_timestamp() {
        let line = "brk(NULL) = 0x55772af19000";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0);
        assert_eq!(entry.timestamp, "");
        assert_eq!(entry.syscall_name, "brk");
        assert_eq!(entry.arguments, "NULL");
        assert_eq!(entry.return_value, Some("0x55772af19000".to_string()));
    }

    #[test]
    fn test_parse_no_timestamp_with_errno() {
        let line = "access(\"/etc/ld.so.preload\", R_OK) = -1 ENOENT (No such file or directory)";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 0);
        assert_eq!(entry.timestamp, "");
        assert_eq!(entry.syscall_name, "access");
        assert_eq!(entry.return_value, Some("-1".to_string()));
        assert!(entry.errno.is_some());
        let errno = entry.errno.unwrap();
        assert_eq!(errno.code, "ENOENT");
    }

    #[test]
    fn test_parse_pid_no_timestamp_exit() {
        let line = "172330 +++ exited with 0 +++";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 172330);
        assert_eq!(entry.timestamp, "");
        assert_eq!(entry.syscall_name, "exit");
        assert!(entry.exit_info.is_some());
        assert_eq!(entry.exit_info.unwrap().code, 0);
    }

    #[test]
    fn test_parse_clone3_resumed_with_extra_output() {
        // clone3 has special output format: => {parent_tid=[PID]}, size) = PID
        let line = "7193  11:52:10.217868 <... clone3 resumed> => {parent_tid=[7197]}, 88) = 7197";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 7193);
        assert_eq!(entry.timestamp, "11:52:10.217868");
        assert_eq!(entry.syscall_name, "clone3");
        assert_eq!(entry.return_value, Some("7197".to_string()));
        assert!(entry.is_resumed);
    }

    #[test]
    fn test_parse_wait4_resumed() {
        // wait4 resumed continues with arguments directly after resumed>
        let line = "24982 12:58:40 <... wait4 resumed>, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 24983";
        let entry = parse_strace_line(line).unwrap();

        assert_eq!(entry.pid, 24982);
        assert_eq!(entry.timestamp, "12:58:40");
        assert_eq!(entry.syscall_name, "wait4");
        assert_eq!(
            entry.arguments,
            ", [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL)"
        );
        assert_eq!(entry.return_value, Some("24983".to_string()));
        assert!(entry.is_resumed);
    }
}
