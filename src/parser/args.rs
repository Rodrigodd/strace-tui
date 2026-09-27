//! Helpers for splitting and decoding raw strace argument strings.
//!
//! Handles the fd annotations printed by `strace -y`/`-yy`, like `3</etc/passwd>`,
//! `0</dev/null<char 1:3>>`, `4<UNIX-STREAM:[1->2]>` or `AT_FDCWD</home>`.

/// Whether the `<` at byte `i` starts an fd annotation (it directly follows an fd
/// number or `AT_FDCWD`, unlike `<unfinished ...>` or `<... resumed>`).
pub fn is_annotation_start(bytes: &[u8], i: usize) -> bool {
    bytes.get(i) == Some(&b'<') && i > 0 && bytes[i - 1].is_ascii_alphanumeric()
}

/// Given the byte index of an annotation's opening `<`, return the index just past its
/// matching `>`. Nested annotations and `[...]`/`{...}` (which may contain `->`) are
/// skipped over. Returns `s.len()` if the annotation is unterminated.
pub fn annotation_end(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut angle = 0usize;
    let mut bracket = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'<' => angle += 1,
            b'[' | b'{' => bracket += 1,
            b']' | b'}' => bracket = bracket.saturating_sub(1),
            b'>' if bracket == 0 => {
                angle -= 1;
                if angle == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Split arguments by comma, handling nested structures, strings and fd annotations
pub fn split_arguments(args: &str) -> Vec<String> {
    let mut result = Vec::new();
    let bytes = args.as_bytes();
    let mut depth = 0i32; // Track nesting depth for (), {}, []
    let mut in_string = false;
    let mut start = 0;
    let mut i = 0;

    let push = |part: &str, result: &mut Vec<String>| {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            result.push(trimmed.to_string());
        }
    };

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'"' => in_string = !in_string,
            _ if in_string => {}
            b'<' if is_annotation_start(bytes, i) => {
                i = annotation_end(args, i);
                continue;
            }
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                push(&args[start..i], &mut result);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }

    // Don't forget the last argument
    push(args.get(start..).unwrap_or(""), &mut result);

    // If we couldn't parse any arguments, return the whole string
    if result.is_empty() && !args.trim().is_empty() {
        result.push(args.trim().to_string());
    }

    result
}

/// Combine the arguments of an `<unfinished ...>` entry with the ones of its
/// `<... resumed>` entry, e.g. `3` and `"data", 10)` into `3, "data", 10`.
pub fn merge_arguments(unfinished: &str, resumed: &str) -> String {
    let resumed = resumed.trim();
    let resumed = resumed.strip_suffix(')').unwrap_or(resumed).trim();
    // `=> {...}` shows the new value of the last in/out argument; keep the original
    if resumed.is_empty() || resumed.starts_with("=>") {
        return unfinished.to_string();
    }
    let resumed_rest = resumed.strip_prefix(',').map(str::trim_start);
    if unfinished.trim().is_empty() {
        return resumed_rest.unwrap_or(resumed).to_string();
    }
    match resumed_rest {
        Some(rest) => format!("{}, {}", unfinished, rest),
        None => format!("{}, {}", unfinished, resumed),
    }
}

/// A file descriptor argument, with its `-y` annotation if present
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdArg<'a> {
    Fd(i32, Option<&'a str>),
    AtFdCwd(Option<&'a str>),
}

/// Split a trailing `<...>` annotation (plus an optional `(deleted)` marker) off `s`.
/// Returns the annotation contents without the outer brackets.
fn split_annotation(s: &str) -> Option<(&str, Option<&str>)> {
    let Some(start) = s.find('<') else {
        return Some((s, None));
    };
    let end = annotation_end(s, start);
    let tail = s[end..].trim();
    if end < start + 2 || !(tail.is_empty() || tail == "(deleted)") {
        return None;
    }
    Some((&s[..start], Some(&s[start + 1..end - 1])))
}

/// Parse an fd argument: `3`, `3</etc/passwd>`, `AT_FDCWD` or `AT_FDCWD</home>`
pub fn parse_fd_arg(arg: &str) -> Option<FdArg<'_>> {
    let (value, annotation) = split_annotation(arg.trim())?;
    if value == "AT_FDCWD" {
        return Some(FdArg::AtFdCwd(annotation));
    }
    value.parse().ok().map(|fd| FdArg::Fd(fd, annotation))
}

/// Parse a return value annotation like `</etc/passwd>(deleted)` that follows the number
pub fn parse_annotation_suffix(s: &str) -> Option<&str> {
    match split_annotation(s)? {
        ("", annotation) => annotation,
        _ => None,
    }
}

/// Parse a quoted string argument, returning its (still escaped) contents
pub fn parse_string_arg(arg: &str) -> Option<&str> {
    let rest = arg.trim().strip_prefix('"')?;
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'"' => return Some(&rest[..i]),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse an fd array like `[3, 4]` or `[3<pipe:[1]>, 4<pipe:[1]>]` (pipe, socketpair)
pub fn parse_fd_array(arg: &str) -> Vec<FdArg<'_>> {
    let Some(inner) = arg
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    else {
        return Vec::new();
    };
    split_ranges(inner, b',')
        .into_iter()
        .filter_map(|(a, b)| parse_fd_arg(&inner[a..b]))
        .collect()
}

/// Parse the fds of a poll list like `[{fd=3, events=POLLIN}, {fd=4<pipe:[1]>, ...}]`
pub fn parse_poll_fds(arg: &str) -> Vec<FdArg<'_>> {
    let Some(inner) = arg
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    else {
        return Vec::new();
    };
    split_ranges(inner, b',')
        .into_iter()
        .filter_map(|(a, b)| {
            let item = inner[a..b].trim();
            let item = item.strip_prefix('{')?.strip_suffix('}')?;
            split_ranges(item, b',')
                .into_iter()
                .find_map(|(a, b)| item[a..b].trim().strip_prefix("fd="))
                .and_then(parse_fd_arg)
        })
        .collect()
}

/// Parse the fds of a select set like `[3 4]` or `[3</a> 5<pipe:[1]>]`
pub fn parse_fd_set(arg: &str) -> Vec<FdArg<'_>> {
    let Some(inner) = arg
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    else {
        return Vec::new();
    };
    split_ranges(inner, b' ')
        .into_iter()
        .filter_map(|(a, b)| parse_fd_arg(&inner[a..b]))
        .collect()
}

/// Byte ranges of `s` separated by `sep` at nesting depth 0, skipping annotations
fn split_ranges(s: &str, sep: u8) -> Vec<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut ranges = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'"' => in_string = !in_string,
            _ if in_string => {}
            b'<' if is_annotation_start(bytes, i) => {
                i = annotation_end(s, i);
                continue;
            }
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            c if c == sep && depth == 0 => {
                if !s[start..i].trim().is_empty() {
                    ranges.push((start, i));
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if !s[start..].trim().is_empty() {
        ranges.push((start, s.len()));
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_split_arguments_with_annotations() {
        assert_eq!(
            split_arguments(r#"4</a,b>, "x, y", 7<{eventfd-count=0, eventfd-id=1}>, 8"#),
            vec![
                "4</a,b>",
                r#""x, y""#,
                "7<{eventfd-count=0, eventfd-id=1}>",
                "8"
            ]
        );
        assert_eq!(
            split_arguments("0</dev/null<char 1:3>>, TCGETS2, 0x7fff"),
            vec!["0</dev/null<char 1:3>>", "TCGETS2", "0x7fff"]
        );
    }

    #[test]
    fn test_merge_arguments() {
        assert_eq!(merge_arguments("3", r#""data", 10)"#), r#"3, "data", 10"#);
        assert_eq!(
            merge_arguments("SIG_SETMASK, [CHLD]", ", NULL, 8)"),
            "SIG_SETMASK, [CHLD], NULL, 8"
        );
        assert_eq!(merge_arguments("", "[3, 4], 0)"), "[3, 4], 0");
        assert_eq!(merge_arguments("5</a>", ")"), "5</a>");
        assert_eq!(
            merge_arguments("{flags=0}, 88", "=> {tid=[1]}, 88)"),
            "{flags=0}, 88"
        );
    }

    #[test]
    fn test_parse_fd_arg() {
        assert_eq!(parse_fd_arg("3"), Some(FdArg::Fd(3, None)));
        assert_eq!(parse_fd_arg("-1"), Some(FdArg::Fd(-1, None)));
        assert_eq!(
            parse_fd_arg("3</etc/passwd>"),
            Some(FdArg::Fd(3, Some("/etc/passwd")))
        );
        assert_eq!(
            parse_fd_arg("0</dev/null<char 1:3>>"),
            Some(FdArg::Fd(0, Some("/dev/null<char 1:3>")))
        );
        assert_eq!(
            parse_fd_arg("4<UNIX-STREAM:[1->2]>"),
            Some(FdArg::Fd(4, Some("UNIX-STREAM:[1->2]")))
        );
        assert_eq!(
            parse_fd_arg("8</memfd:mm>(deleted)"),
            Some(FdArg::Fd(8, Some("/memfd:mm")))
        );
        assert_eq!(parse_fd_arg("AT_FDCWD"), Some(FdArg::AtFdCwd(None)));
        assert_eq!(
            parse_fd_arg("AT_FDCWD</tmp>"),
            Some(FdArg::AtFdCwd(Some("/tmp")))
        );
        assert_eq!(parse_fd_arg("O_RDONLY"), None);
        assert_eq!(parse_fd_arg(r#""/etc""#), None);
    }

    #[test]
    fn test_parse_string_arg() {
        assert_eq!(parse_string_arg(r#""/etc/passwd""#), Some("/etc/passwd"));
        assert_eq!(parse_string_arg(r#""a\"b"..."#), Some(r#"a\"b"#));
        assert_eq!(parse_string_arg("NULL"), None);
    }

    #[test]
    fn test_parse_fd_lists() {
        assert_eq!(
            parse_fd_array("[4<pipe:[9]>, 5<pipe:[9]>]"),
            vec![
                FdArg::Fd(4, Some("pipe:[9]")),
                FdArg::Fd(5, Some("pipe:[9]"))
            ]
        );
        assert_eq!(
            parse_fd_array("[3, 4]"),
            vec![FdArg::Fd(3, None), FdArg::Fd(4, None)]
        );
        assert_eq!(
            parse_poll_fds("[{fd=3, events=POLLIN}, {fd=4<pipe:[1]>, events=POLLOUT}]"),
            vec![FdArg::Fd(3, None), FdArg::Fd(4, Some("pipe:[1]"))]
        );
        assert_eq!(
            parse_fd_set("[3</a b> 5]"),
            vec![FdArg::Fd(3, Some("/a b")), FdArg::Fd(5, None)]
        );
        assert_eq!(parse_fd_set("NULL"), vec![]);
    }
}
