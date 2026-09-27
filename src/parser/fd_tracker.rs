//! Tracks file descriptors across a trace and groups every syscall that touched a file,
//! pipe, socket or other fd-backed resource.
//!
//! fds are followed through dup/dup2/dup3/fcntl(F_DUPFD), inherited by fork/clone
//! (shared with CLONE_FILES), and dropped by close, close-on-exec and process exit.
//! When the trace was recorded with `strace -y`/`-yy`, the fd annotations give the
//! resource names; otherwise names are derived from the syscall that created the fd.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::Serialize;

use super::SyscallEntry;
use super::args::{
    FdArg, merge_arguments, parse_fd_arg, parse_fd_array, parse_fd_set, parse_poll_fds,
    parse_string_arg, split_arguments,
};

/// What kind of object a resource is
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    File,
    Directory,
    Device,
    Pipe,
    Socket,
    EventFd,
    Epoll,
    TimerFd,
    SignalFd,
    Inotify,
    MemFd,
    PidFd,
    /// Other anonymous inodes (fanotify, userfaultfd, io_uring, ...)
    Anon,
    Unknown,
}

impl ResourceKind {
    pub fn label(self) -> &'static str {
        match self {
            ResourceKind::File => "file",
            ResourceKind::Directory => "dir",
            ResourceKind::Device => "dev",
            ResourceKind::Pipe => "pipe",
            ResourceKind::Socket => "socket",
            ResourceKind::EventFd => "eventfd",
            ResourceKind::Epoll => "epoll",
            ResourceKind::TimerFd => "timerfd",
            ResourceKind::SignalFd => "signalfd",
            ResourceKind::Inotify => "inotify",
            ResourceKind::MemFd => "memfd",
            ResourceKind::PidFd => "pidfd",
            ResourceKind::Anon => "anon",
            ResourceKind::Unknown => "fd",
        }
    }
}

/// Aggregated counters over a set of accesses
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AccessStats {
    /// Number of syscalls
    pub calls: usize,
    /// Number of failed syscalls
    pub errors: usize,
    /// Bytes successfully read (read, recv, the input side of sendfile, ...)
    pub bytes_read: u64,
    /// Bytes successfully written (write, send, the output side of sendfile, ...)
    pub bytes_written: u64,
}

/// A syscall that touched a resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileAccess {
    /// Index of the syscall entry (the `<unfinished ...>` half for split syscalls)
    pub entry_idx: usize,
    pub pid: u32,
    /// The fd used, if the access went through one
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
}

/// How an fd lifetime ended
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifetimeEnd {
    /// The last fd referring to it was closed (or replaced by dup2)
    Closed { entry_idx: usize },
    /// The last fd referring to it was close-on-exec
    CloseOnExec { entry_idx: usize },
    /// The last process holding it exited
    ProcessExit { entry_idx: usize },
    /// Still open at the end of the trace
    StillOpen,
}

/// A pid/fd pair referring to an fd lifetime
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FdAlias {
    pub pid: u32,
    pub fd: i32,
}

/// One open file description: from the syscall that created it until the last fd
/// referring to it (including dups and fds inherited by children) is gone
#[derive(Debug, Clone, Serialize)]
pub struct FdLifetime {
    /// Syscall that created it, `None` if it was inherited from before the trace
    pub open_entry_idx: Option<usize>,
    /// Open flags, socket type, pipe end, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// Every pid/fd that referred to it, the first one being the original
    pub aliases: Vec<FdAlias>,
    pub end: LifetimeEnd,
    pub accesses: Vec<FileAccess>,
    pub stats: AccessStats,
    /// Number of fd table slots still referring to it
    #[serde(skip)]
    open_slots: usize,
}

/// A file, directory, pipe, socket, ... touched by the trace
#[derive(Debug, Clone, Serialize)]
pub struct FileResource {
    /// Path for files, the `-y` annotation or a description for other resources
    pub name: String,
    pub kind: ResourceKind,
    /// First syscall that touched it
    pub first_entry_idx: usize,
    pub lifetimes: Vec<FdLifetime>,
    /// Accesses by path that did not create an fd (stat, access, unlink, failed opens...)
    pub path_accesses: Vec<FileAccess>,
    pub stats: AccessStats,
    /// PIDs that touched it
    pub pids: Vec<u32>,
    #[serde(skip)]
    last_entry: Option<usize>,
}

impl FileResource {
    /// Whether every access to this resource failed (e.g. a path that doesn't exist)
    pub fn all_failed(&self) -> bool {
        self.stats.calls > 0 && self.stats.errors == self.stats.calls
    }
}

/// A resource referenced by one argument (or the return value) of a syscall entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRef {
    /// Argument index into `split_arguments(&entry.arguments)`, or `None` for the
    /// return value
    pub arg_idx: Option<usize>,
    pub resource: usize,
    /// `None` for path accesses that did not go through an fd
    pub lifetime: Option<usize>,
}

/// Result of [`analyze_files`]
#[derive(Debug, Clone, Default, Serialize)]
pub struct FileAnalysis {
    /// Resources ordered by first access
    pub resources: Vec<FileResource>,
    /// Resources referenced by each entry
    #[serde(skip)]
    pub by_entry: HashMap<usize, Vec<ResourceRef>>,
}

impl FileAnalysis {
    /// Resources referenced by an entry's arguments and return value
    pub fn refs(&self, entry_idx: usize) -> &[ResourceRef] {
        self.by_entry.get(&entry_idx).map_or(&[], Vec::as_slice)
    }
}

/// Analyze which resources every syscall touched
pub fn analyze_files(entries: &[SyscallEntry]) -> FileAnalysis {
    let mut tracker = Tracker::new(entries);
    for idx in 0..entries.len() {
        tracker.process(idx);
    }
    tracker.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Io {
    None,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    lifetime: (usize, usize),
    cloexec: bool,
}

#[derive(Debug, Default)]
struct FdTable {
    fds: BTreeMap<i32, Slot>,
    /// Number of processes sharing this table
    users: usize,
}

#[derive(Debug, Clone, Copy)]
struct ChildInfo {
    parent: u32,
    share_files: bool,
    share_fs: bool,
}

/// A syscall being processed, with the halves of split syscalls combined
struct Call<'a> {
    /// Entry where the syscall starts, used for accesses
    start_idx: usize,
    /// Entry with the return value
    ret_idx: usize,
    /// Number of arguments in the `start_idx` entry, when it differs from `ret_idx`
    first_args: usize,
    pid: u32,
    name: &'a str,
    args: Vec<String>,
    ret: Option<i64>,
    ret_annotation: Option<&'a str>,
    errno: Option<&'a str>,
}

impl Call<'_> {
    fn arg(&self, i: usize) -> &str {
        self.args.get(i).map_or("", String::as_str)
    }

    fn failed(&self) -> bool {
        self.errno.is_some()
    }

    /// Whether the syscall completed successfully
    fn ok(&self) -> bool {
        !self.failed() && self.ret.is_some()
    }

    fn ret_fd(&self) -> Option<i32> {
        self.ret
            .filter(|_| self.ok())
            .and_then(|r| i32::try_from(r).ok())
            .filter(|&fd| fd >= 0)
    }

    fn arg_fd(&self, i: usize) -> Option<i32> {
        match parse_fd_arg(self.arg(i))? {
            FdArg::Fd(fd, _) if fd >= 0 => Some(fd),
            _ => None,
        }
    }
}

fn is_fork_syscall(name: &str) -> bool {
    matches!(name, "fork" | "vfork" | "clone" | "clone2" | "clone3")
}

fn parse_ret(value: &str) -> Option<i64> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok().map(|v| v as i64),
        None => value.parse().ok(),
    }
}

/// Lexically normalize an absolute path, resolving `.` and `..`
fn normalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Resolve `path` against `base` (a directory), if the path is relative
fn resolve_path(base: Option<&str>, path: &str) -> String {
    if path.starts_with('/') {
        normalize_path(path)
    } else if let Some(base) = base.filter(|b| b.starts_with('/')) {
        normalize_path(&format!("{}/{}", base, path))
    } else {
        path.to_string()
    }
}

/// Strip a nested annotation like the `<char 1:3>` in `/dev/null<char 1:3>`
fn strip_nested(annotation: &str) -> &str {
    annotation
        .find('<')
        .map_or(annotation, |i| &annotation[..i])
}

/// Derive a resource name and kind from an fd annotation. Returns whether the name
/// identifies the underlying object (so equal names refer to the same resource).
fn classify_annotation(annotation: &str, hint: ResourceKind) -> (String, ResourceKind, bool) {
    if annotation.starts_with('/') {
        let path = strip_nested(annotation);
        let kind = if path.starts_with("/memfd:") {
            ResourceKind::MemFd
        } else if path.len() != annotation.len() || path.starts_with("/dev/") {
            ResourceKind::Device
        } else if hint == ResourceKind::Directory {
            hint
        } else {
            ResourceKind::File
        };
        return (path.to_string(), kind, kind != ResourceKind::MemFd);
    }
    if annotation.starts_with("pipe:[") {
        return (annotation.to_string(), ResourceKind::Pipe, true);
    }
    if let Some(inner) = annotation.strip_prefix("anon_inode:") {
        let kind = match inner.trim_matches(['[', ']']) {
            "eventpoll" => ResourceKind::Epoll,
            "eventfd" => ResourceKind::EventFd,
            "timerfd" => ResourceKind::TimerFd,
            "signalfd" => ResourceKind::SignalFd,
            "inotify" => ResourceKind::Inotify,
            "pidfd" => ResourceKind::PidFd,
            _ if hint != ResourceKind::Unknown => hint,
            _ => ResourceKind::Anon,
        };
        return (annotation.to_string(), kind, false);
    }
    if annotation.starts_with('{') {
        // -yy prints eventfd state like {eventfd-count=0, eventfd-id=271, ...}
        if let Some(id) = annotation
            .split(['{', '}', ',', ' '])
            .find_map(|part| part.strip_prefix("eventfd-id="))
        {
            return (format!("eventfd:[{}]", id), ResourceKind::EventFd, true);
        }
        return (annotation.to_string(), hint, false);
    }
    if annotation.contains(":[") {
        // socket:[123], TCP:[1.2.3.4:5->6.7.8.9:10], UNIX-STREAM:[1->2], NETLINK:[...]
        return (annotation.to_string(), ResourceKind::Socket, true);
    }
    (annotation.to_string(), hint, false)
}

/// Syscalls whose first argument is an fd, with no other resource arguments
const FD_FIRST_SYSCALLS: &[&str] = &[
    "lseek",
    "_llseek",
    "fstat",
    "fstat64",
    "fstatfs",
    "fstatfs64",
    "fsync",
    "fdatasync",
    "ftruncate",
    "ftruncate64",
    "fchmod",
    "fchown",
    "fchown32",
    "ioctl",
    "flock",
    "fadvise64",
    "fadvise64_64",
    "fallocate",
    "readahead",
    "sync_file_range",
    "syncfs",
    "connect",
    "bind",
    "listen",
    "shutdown",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "sendmmsg",
    "recvmmsg",
    "fgetxattr",
    "fsetxattr",
    "flistxattr",
    "fremovexattr",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "inotify_rm_watch",
    "timerfd_settime",
    "timerfd_gettime",
    "io_uring_enter",
    "io_uring_register",
    "pidfd_send_signal",
    "fanotify_mark",
    "fsconfig",
    "futimesat",
    "fchmodat2",
];

/// Syscalls taking `(dirfd, path, ...)`
const PATH_AT_SYSCALLS: &[&str] = &[
    "newfstatat",
    "fstatat64",
    "statx",
    "faccessat",
    "faccessat2",
    "mkdirat",
    "unlinkat",
    "readlinkat",
    "fchmodat",
    "fchownat",
    "utimensat",
    "mknodat",
    "name_to_handle_at",
    "getxattrat",
    "setxattrat",
    "listxattrat",
    "removexattrat",
];

/// Syscalls taking a path as their first argument
const PATH_SYSCALLS: &[&str] = &[
    "stat",
    "stat64",
    "lstat",
    "lstat64",
    "access",
    "readlink",
    "unlink",
    "rmdir",
    "mkdir",
    "chmod",
    "chown",
    "chown32",
    "lchown",
    "lchown32",
    "truncate",
    "truncate64",
    "statfs",
    "statfs64",
    "utime",
    "utimes",
    "mknod",
    "getxattr",
    "lgetxattr",
    "setxattr",
    "lsetxattr",
    "listxattr",
    "llistxattr",
    "removexattr",
    "lremovexattr",
    "chroot",
    "acct",
    "swapon",
    "swapoff",
    "uselib",
    "umount2",
];

struct Tracker<'a> {
    entries: &'a [SyscallEntry],
    resources: Vec<FileResource>,
    by_name: HashMap<String, usize>,
    by_entry: HashMap<usize, Vec<ResourceRef>>,
    tables: Vec<FdTable>,
    pid_table: HashMap<u32, usize>,
    /// Working directories, shared between processes created with CLONE_FS
    cwds: Vec<Option<String>>,
    pid_cwd: HashMap<u32, usize>,
    /// Forks that created each pid, in trace order (pids may be reused)
    children: HashMap<u32, VecDeque<ChildInfo>>,
}

impl<'a> Tracker<'a> {
    fn new(entries: &'a [SyscallEntry]) -> Self {
        let mut tracker = Tracker {
            entries,
            resources: Vec::new(),
            by_name: HashMap::new(),
            by_entry: HashMap::new(),
            tables: Vec::new(),
            pid_table: HashMap::new(),
            cwds: Vec::new(),
            pid_cwd: HashMap::new(),
            children: HashMap::new(),
        };

        // A child may run before its parent's fork returns, so find out beforehand
        // which fork created each pid
        for idx in 0..entries.len() {
            if let Some(call) = tracker.call(idx)
                && is_fork_syscall(call.name)
                && let Some(child) = call.ret.filter(|&r| r > 0 && call.ok())
            {
                let flags = call.args.join(",");
                tracker
                    .children
                    .entry(child as u32)
                    .or_default()
                    .push_back(ChildInfo {
                        parent: call.pid,
                        share_files: flags.contains("CLONE_FILES"),
                        share_fs: flags.contains("CLONE_FS"),
                    });
            }
        }

        tracker
    }

    /// Build the call for an entry, or `None` if the entry is not a syscall or is the
    /// first half of a split syscall (which is processed with its second half)
    fn call(&self, idx: usize) -> Option<Call<'a>> {
        let entries = self.entries;
        let entry = &entries[idx];
        if entry.exit_info.is_some() || entry.signal.is_some() {
            return None;
        }
        if entry.is_unfinished && entry.resumed_entry_idx.is_some() {
            return None;
        }

        let (start_idx, args, first_args) = match entry.unfinished_entry_idx {
            Some(start) if entry.is_resumed => {
                let first = &entries[start].arguments;
                (
                    start,
                    merge_arguments(first, &entry.arguments),
                    split_arguments(first).len(),
                )
            }
            _ => (idx, entry.arguments.clone(), 0),
        };

        Some(Call {
            start_idx,
            ret_idx: idx,
            first_args,
            pid: entry.pid,
            name: entry.syscall_name.as_str(),
            args: split_arguments(&args),
            ret: entry.return_value.as_deref().and_then(parse_ret),
            ret_annotation: entry.return_annotation.as_deref(),
            errno: entry.errno.as_ref().map(|e| e.code.as_str()),
        })
    }

    fn finish(mut self) -> FileAnalysis {
        // Split syscalls are processed at their second half, so restore trace order
        let mut order: Vec<usize> = (0..self.resources.len()).collect();
        order.sort_by_key(|&r| self.resources[r].first_entry_idx);
        let mut new_id = vec![0; order.len()];
        for (new, &old) in order.iter().enumerate() {
            new_id[old] = new;
        }

        let mut old_resources: Vec<Option<FileResource>> =
            self.resources.into_iter().map(Some).collect();
        let resources = order
            .iter()
            .map(|&old| {
                let mut resource = old_resources[old].take().unwrap();
                resource.pids.sort_unstable();
                resource
            })
            .collect();

        for refs in self.by_entry.values_mut() {
            for r in refs.iter_mut() {
                r.resource = new_id[r.resource];
            }
        }

        FileAnalysis {
            resources,
            by_entry: self.by_entry,
        }
    }

    fn process(&mut self, idx: usize) {
        let entries = self.entries;
        let entry = &entries[idx];
        if entry.exit_info.is_some() {
            self.process_exit(entry.pid, idx);
            return;
        }
        let Some(call) = self.call(idx) else {
            return;
        };
        self.ensure_pid(call.pid);

        match call.name {
            "open" => self.open(&call, None, 0, 1),
            "creat" => self.open(&call, None, 0, 1),
            "openat" | "openat2" => self.open(&call, Some(0), 1, 2),
            "open_by_handle_at" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.create_from_ret(&call, ResourceKind::File, "open_by_handle_at");
            }

            "read" | "pread64" | "readv" | "preadv" | "preadv2" | "recv" | "recvfrom"
            | "recvmsg" => {
                self.use_fd_arg(&call, 0, Io::Read);
            }
            "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2" | "send" | "sendto"
            | "sendmsg" => {
                self.use_fd_arg(&call, 0, Io::Write);
            }
            "sendfile" | "sendfile64" => {
                self.use_fd_arg(&call, 0, Io::Write);
                self.use_fd_arg(&call, 1, Io::Read);
            }
            "splice" | "copy_file_range" => {
                self.use_fd_arg(&call, 0, Io::Read);
                self.use_fd_arg(&call, 2, Io::Write);
            }
            "tee" => {
                self.use_fd_arg(&call, 0, Io::Read);
                self.use_fd_arg(&call, 1, Io::Write);
            }
            "mmap" | "mmap2" => {
                self.use_fd_arg(&call, 4, Io::None);
            }
            "getdents" | "getdents64" | "fchdir" => {
                if let Some((res, _)) = self.use_fd_arg(&call, 0, Io::None) {
                    self.mark_dir(res);
                    if call.name == "fchdir" && call.ok() {
                        let name = self.resources[res].name.clone();
                        self.set_cwd(call.pid, &name);
                    }
                }
            }
            "fstat" | "fstat64" if call.args.iter().any(|a| a.contains("S_IFDIR")) => {
                if let Some((res, _)) = self.use_fd_arg(&call, 0, Io::None) {
                    self.mark_dir(res);
                }
            }

            "close" => self.close(&call),
            "close_range" => self.close_range(&call),
            "dup" => self.dup(&call, call.ret_fd(), false),
            "dup2" | "dup3" => {
                let target = call.arg_fd(1).filter(|_| call.ok());
                let cloexec = call.arg(2).contains("O_CLOEXEC");
                self.dup(&call, target, cloexec);
            }
            "fcntl" | "fcntl64" => self.fcntl(&call),

            "pipe" | "pipe2" => self.create_pair(&call, 0, ResourceKind::Pipe),
            "socketpair" => self.create_pair(&call, 3, ResourceKind::Socket),
            "socket" => {
                let label = format!("socket({})", call.arg(0));
                self.create_from_ret(&call, ResourceKind::Socket, &label);
            }
            "accept" | "accept4" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.create_from_ret(&call, ResourceKind::Socket, "accept");
            }
            "eventfd" | "eventfd2" => self.create_from_ret(&call, ResourceKind::EventFd, "eventfd"),
            "epoll_create" | "epoll_create1" => {
                self.create_from_ret(&call, ResourceKind::Epoll, "epoll")
            }
            "timerfd_create" => self.create_from_ret(&call, ResourceKind::TimerFd, "timerfd"),
            "signalfd" | "signalfd4" => {
                if call.arg_fd(0).is_some() {
                    self.use_fd_arg(&call, 0, Io::None);
                } else {
                    self.create_from_ret(&call, ResourceKind::SignalFd, "signalfd");
                }
            }
            "inotify_init" | "inotify_init1" => {
                self.create_from_ret(&call, ResourceKind::Inotify, "inotify")
            }
            "inotify_add_watch" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.path_access(&call, None, 1);
            }
            "memfd_create" | "memfd_secret" => {
                let label = format!("memfd {}", call.arg(0));
                self.create_from_ret(&call, ResourceKind::MemFd, &label);
            }
            "pidfd_open" => {
                let label = format!("pidfd {}", call.arg(0));
                self.create_from_ret(&call, ResourceKind::PidFd, &label);
            }
            "pidfd_getfd" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.create_from_ret(&call, ResourceKind::Unknown, "pidfd_getfd");
            }
            "fanotify_init" | "userfaultfd" | "perf_event_open" | "io_uring_setup" | "fsopen" => {
                let name = call.name;
                self.create_from_ret(&call, ResourceKind::Anon, name);
            }
            "fsmount" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.create_from_ret(&call, ResourceKind::Anon, "fsmount");
            }
            "open_tree" | "fspick" => {
                self.path_access(&call, Some(0), 1);
                let name = call.name;
                self.create_from_ret(&call, ResourceKind::Anon, name);
            }

            "epoll_ctl" => {
                self.use_fd_arg(&call, 0, Io::None);
                self.use_fd_arg(&call, 2, Io::None);
            }
            "poll" | "ppoll" => {
                for fd in parse_poll_fds(call.arg(0)) {
                    self.use_fd(&call, 0, fd, Io::None);
                }
            }
            "select" | "_newselect" | "pselect6" => {
                for arg_idx in 1..=3 {
                    for fd in parse_fd_set(call.arg(arg_idx)) {
                        self.use_fd(&call, arg_idx, fd, Io::None);
                    }
                }
            }

            "chdir" => {
                if let Some(res) = self.path_access(&call, None, 0)
                    && call.ok()
                {
                    self.mark_dir(res);
                    let name = self.resources[res].name.clone();
                    self.set_cwd(call.pid, &name);
                }
            }
            "mkdir" | "rmdir" => {
                if let Some(res) = self.path_access(&call, None, 0)
                    && call.ok()
                {
                    self.mark_dir(res);
                }
            }
            "mkdirat" => {
                if let Some(res) = self.path_access(&call, Some(0), 1)
                    && call.ok()
                {
                    self.mark_dir(res);
                }
            }
            "rename" | "link" => {
                self.path_access(&call, None, 0);
                self.path_access(&call, None, 1);
            }
            "symlink" => {
                self.path_access(&call, None, 1);
            }
            "renameat" | "renameat2" | "linkat" => {
                self.path_access(&call, Some(0), 1);
                self.path_access(&call, Some(2), 3);
            }
            "symlinkat" => {
                self.path_access(&call, Some(1), 2);
            }
            "execve" => {
                self.path_access(&call, None, 0);
                if call.ok() {
                    self.exec(&call);
                }
            }
            "execveat" => {
                self.path_access(&call, Some(0), 1);
                if call.ok() {
                    self.exec(&call);
                }
            }
            name if is_fork_syscall(name) => {
                if let Some(child) = call.ret.filter(|&r| r > 0 && call.ok()) {
                    self.ensure_pid(child as u32);
                }
            }

            name if PATH_AT_SYSCALLS.contains(&name) => {
                let res = self.path_access(&call, Some(0), 1);
                if let Some(res) = res
                    && call.args.iter().any(|a| a.contains("S_IFDIR"))
                {
                    self.mark_dir(res);
                }
            }
            name if PATH_SYSCALLS.contains(&name) => {
                let res = self.path_access(&call, None, 0);
                if let Some(res) = res
                    && call.args.iter().any(|a| a.contains("S_IFDIR"))
                {
                    self.mark_dir(res);
                }
            }
            name if FD_FIRST_SYSCALLS.contains(&name) => {
                self.use_fd_arg(&call, 0, Io::None);
            }

            // Unknown syscall: with -y, annotated arguments are known to be fds
            _ => {
                for arg_idx in 0..call.args.len() {
                    if let Some(fd @ FdArg::Fd(_, Some(_))) = parse_fd_arg(call.arg(arg_idx)) {
                        self.use_fd(&call, arg_idx, fd, Io::None);
                    }
                }
            }
        }
    }

    // ----- Process state -----

    /// Set up the fd table and cwd of a pid seen for the first time
    fn ensure_pid(&mut self, pid: u32) {
        if self.pid_table.contains_key(&pid) {
            return;
        }
        let info = self
            .children
            .get_mut(&pid)
            .and_then(VecDeque::pop_front)
            .filter(|info| info.parent != pid);

        let Some(info) = info else {
            self.tables.push(FdTable {
                fds: BTreeMap::new(),
                users: 1,
            });
            self.pid_table.insert(pid, self.tables.len() - 1);
            self.cwds.push(None);
            self.pid_cwd.insert(pid, self.cwds.len() - 1);
            return;
        };

        self.ensure_pid(info.parent);
        let parent_table = self.pid_table[&info.parent];
        let table = if info.share_files {
            self.tables[parent_table].users += 1;
            parent_table
        } else {
            let fds = self.tables[parent_table].fds.clone();
            for (&fd, slot) in &fds {
                let (res, lt) = slot.lifetime;
                let lifetime = &mut self.resources[res].lifetimes[lt];
                lifetime.open_slots += 1;
                let alias = FdAlias { pid, fd };
                if !lifetime.aliases.contains(&alias) {
                    lifetime.aliases.push(alias);
                }
            }
            self.tables.push(FdTable { fds, users: 1 });
            self.tables.len() - 1
        };
        self.pid_table.insert(pid, table);

        let parent_cwd = self.pid_cwd[&info.parent];
        let cwd = if info.share_fs {
            parent_cwd
        } else {
            self.cwds.push(self.cwds[parent_cwd].clone());
            self.cwds.len() - 1
        };
        self.pid_cwd.insert(pid, cwd);
    }

    fn table_of(&mut self, pid: u32) -> usize {
        self.ensure_pid(pid);
        self.pid_table[&pid]
    }

    fn cwd(&mut self, pid: u32) -> Option<String> {
        self.ensure_pid(pid);
        self.cwds[self.pid_cwd[&pid]].clone()
    }

    fn set_cwd(&mut self, pid: u32, path: &str) {
        if path.starts_with('/') {
            self.ensure_pid(pid);
            self.cwds[self.pid_cwd[&pid]] = Some(path.to_string());
        }
    }

    fn process_exit(&mut self, pid: u32, idx: usize) {
        self.pid_cwd.remove(&pid);
        let Some(table) = self.pid_table.remove(&pid) else {
            return;
        };
        self.tables[table].users -= 1;
        if self.tables[table].users == 0 {
            let fds = std::mem::take(&mut self.tables[table].fds);
            for slot in fds.values() {
                self.release(slot.lifetime, LifetimeEnd::ProcessExit { entry_idx: idx });
            }
        }
    }

    /// Drop the close-on-exec fds of a process that successfully called execve
    fn exec(&mut self, call: &Call) {
        let table = self.table_of(call.pid);
        let end = LifetimeEnd::CloseOnExec {
            entry_idx: call.start_idx,
        };
        if self.tables[table].users > 1 {
            // execve unshares the fd table
            let fds: BTreeMap<i32, Slot> = self.tables[table]
                .fds
                .iter()
                .filter(|(_, slot)| !slot.cloexec)
                .map(|(&fd, &slot)| (fd, slot))
                .collect();
            for slot in fds.values() {
                let (res, lt) = slot.lifetime;
                self.resources[res].lifetimes[lt].open_slots += 1;
            }
            self.tables[table].users -= 1;
            self.tables.push(FdTable { fds, users: 1 });
            self.pid_table.insert(call.pid, self.tables.len() - 1);
        } else {
            let closing: Vec<i32> = self.tables[table]
                .fds
                .iter()
                .filter(|(_, slot)| slot.cloexec)
                .map(|(&fd, _)| fd)
                .collect();
            for fd in closing {
                if let Some(slot) = self.tables[table].fds.remove(&fd) {
                    self.release(slot.lifetime, end);
                }
            }
        }
    }

    // ----- Resources and lifetimes -----

    fn new_resource(&mut self, name: String, kind: ResourceKind, idx: usize, keyed: bool) -> usize {
        let id = self.resources.len();
        if keyed {
            self.by_name.insert(name.clone(), id);
        }
        self.resources.push(FileResource {
            name,
            kind,
            first_entry_idx: idx,
            lifetimes: Vec::new(),
            path_accesses: Vec::new(),
            stats: AccessStats::default(),
            pids: Vec::new(),
            last_entry: None,
        });
        id
    }

    fn path_resource(&mut self, path: &str, idx: usize) -> usize {
        match self.by_name.get(path) {
            Some(&id) => id,
            None => {
                let kind = if path.starts_with("/dev/") {
                    ResourceKind::Device
                } else {
                    ResourceKind::File
                };
                self.new_resource(path.to_string(), kind, idx, true)
            }
        }
    }

    /// Resource for an fd annotated by `strace -y`, e.g. `/etc/passwd` or `pipe:[123]`
    fn annotated_resource(
        &mut self,
        annotation: &str,
        hint: ResourceKind,
        pid: u32,
        fd: i32,
        idx: usize,
    ) -> usize {
        let (name, kind, keyed) = classify_annotation(annotation, hint);
        if keyed {
            if let Some(&id) = self.by_name.get(&name) {
                return id;
            }
            return self.new_resource(name, kind, idx, true);
        }
        let name = format!("{} [pid {}, fd {}]", name, pid, fd);
        self.new_resource(name, kind, idx, false)
    }

    fn mark_dir(&mut self, res: usize) {
        let kind = &mut self.resources[res].kind;
        if matches!(kind, ResourceKind::File | ResourceKind::Unknown) {
            *kind = ResourceKind::Directory;
        }
    }

    fn new_lifetime(
        &mut self,
        call: &Call,
        res: usize,
        fd: i32,
        flags: Option<String>,
        cloexec: bool,
    ) -> usize {
        let table = self.table_of(call.pid);
        // The fd was closed without us noticing (e.g. by a missing line)
        if let Some(old) = self.tables[table].fds.remove(&fd) {
            self.release(
                old.lifetime,
                LifetimeEnd::Closed {
                    entry_idx: call.start_idx,
                },
            );
        }
        let lifetimes = &mut self.resources[res].lifetimes;
        lifetimes.push(FdLifetime {
            open_entry_idx: Some(call.start_idx),
            flags: flags.filter(|f| !f.is_empty() && f != "0"),
            aliases: vec![FdAlias { pid: call.pid, fd }],
            end: LifetimeEnd::StillOpen,
            accesses: Vec::new(),
            stats: AccessStats::default(),
            open_slots: 1,
        });
        let lt = lifetimes.len() - 1;
        self.tables[table].fds.insert(
            fd,
            Slot {
                lifetime: (res, lt),
                cloexec,
            },
        );
        lt
    }

    /// Drop one fd table slot referring to a lifetime
    fn release(&mut self, (res, lt): (usize, usize), end: LifetimeEnd) {
        let lifetime = &mut self.resources[res].lifetimes[lt];
        lifetime.open_slots = lifetime.open_slots.saturating_sub(1);
        if lifetime.open_slots == 0 {
            lifetime.end = end;
        }
    }

    /// Find the lifetime an fd refers to, creating an inherited one for fds opened
    /// before the trace started
    fn lookup_fd(
        &mut self,
        call: &Call,
        fd: i32,
        annotation: Option<&str>,
    ) -> Option<(usize, usize)> {
        if fd < 0 {
            return None;
        }
        let table = self.table_of(call.pid);
        if let Some(slot) = self.tables[table].fds.get(&fd) {
            return Some(slot.lifetime);
        }
        if call.errno == Some("EBADF") {
            return None;
        }

        let res = match annotation {
            Some(annotation) => self.annotated_resource(
                annotation,
                ResourceKind::Unknown,
                call.pid,
                fd,
                call.start_idx,
            ),
            None => self.new_resource(
                format!("fd {} (inherited by pid {})", fd, call.pid),
                ResourceKind::Unknown,
                call.start_idx,
                false,
            ),
        };
        let lifetimes = &mut self.resources[res].lifetimes;
        lifetimes.push(FdLifetime {
            open_entry_idx: None,
            flags: None,
            aliases: vec![FdAlias { pid: call.pid, fd }],
            end: LifetimeEnd::StillOpen,
            accesses: Vec::new(),
            stats: AccessStats::default(),
            open_slots: 1,
        });
        let lifetime = (res, lifetimes.len() - 1);
        self.tables[table].fds.insert(
            fd,
            Slot {
                lifetime,
                cloexec: false,
            },
        );
        Some(lifetime)
    }

    // ----- Accesses -----

    /// Record that a call touched a resource, through an fd lifetime or by path
    fn access(&mut self, call: &Call, res: usize, lt: Option<usize>, fd: Option<i32>, io: Io) {
        let resource = &mut self.resources[res];
        let access = FileAccess {
            entry_idx: call.start_idx,
            pid: call.pid,
            fd,
        };
        let bytes = call
            .ret
            .filter(|&r| r > 0 && call.ok() && io != Io::None)
            .unwrap_or(0) as u64;
        let add_bytes = |stats: &mut AccessStats| match io {
            Io::Read => stats.bytes_read += bytes,
            Io::Write => stats.bytes_written += bytes,
            Io::None => {}
        };

        match lt {
            Some(lt) => {
                let lifetime = &mut resource.lifetimes[lt];
                if lifetime.accesses.last().map(|a| a.entry_idx) == Some(call.start_idx) {
                    return;
                }
                lifetime.accesses.push(access);
                lifetime.stats.calls += 1;
                lifetime.stats.errors += call.failed() as usize;
                add_bytes(&mut lifetime.stats);
            }
            None => {
                if resource.path_accesses.last().map(|a| a.entry_idx) == Some(call.start_idx) {
                    return;
                }
                resource.path_accesses.push(access);
            }
        }

        // A call may touch several lifetimes of one resource (e.g. both pipe ends)
        if resource.last_entry != Some(call.start_idx) {
            resource.last_entry = Some(call.start_idx);
            resource.stats.calls += 1;
            resource.stats.errors += call.failed() as usize;
        }
        add_bytes(&mut resource.stats);
        resource.first_entry_idx = resource.first_entry_idx.min(call.start_idx);
        if !resource.pids.contains(&call.pid) {
            resource.pids.push(call.pid);
        }
    }

    /// Record that an argument (or the return value, for `None`) refers to a resource
    fn add_ref(&mut self, call: &Call, arg_idx: Option<usize>, res: usize, lt: Option<usize>) {
        // For split syscalls, arguments belong to either half
        let (idx, arg_idx) = match arg_idx {
            Some(a) if call.start_idx != call.ret_idx && a >= call.first_args => {
                (call.ret_idx, Some(a - call.first_args))
            }
            Some(a) => (call.start_idx, Some(a)),
            None => (call.ret_idx, None),
        };
        let r = ResourceRef {
            arg_idx,
            resource: res,
            lifetime: lt,
        };
        let refs = self.by_entry.entry(idx).or_default();
        if !refs.contains(&r) {
            refs.push(r);
        }
    }

    /// Record an access through an fd argument
    fn use_fd_arg(&mut self, call: &Call, arg_idx: usize, io: Io) -> Option<(usize, usize)> {
        let fd = parse_fd_arg(call.arg(arg_idx))?;
        self.use_fd(call, arg_idx, fd, io)
    }

    fn use_fd(&mut self, call: &Call, arg_idx: usize, fd: FdArg, io: Io) -> Option<(usize, usize)> {
        match fd {
            FdArg::AtFdCwd(annotation) => {
                if let Some(cwd) = annotation {
                    self.set_cwd(call.pid, strip_nested(cwd));
                }
                None
            }
            FdArg::Fd(fd, annotation) => {
                let (res, lt) = self.lookup_fd(call, fd, annotation)?;
                self.access(call, res, Some(lt), Some(fd), io);
                self.add_ref(call, Some(arg_idx), res, Some(lt));
                Some((res, lt))
            }
        }
    }

    /// Directory a path argument is relative to, recording the dirfd access. With an
    /// empty path (AT_EMPTY_PATH), the dirfd may be any kind of file.
    fn dir_base(
        &mut self,
        call: &Call,
        dirfd_arg: Option<usize>,
        empty_path: bool,
    ) -> Option<String> {
        let fd = dirfd_arg.and_then(|d| Some((d, parse_fd_arg(call.arg(d))?)));
        match fd {
            Some((d, fd @ FdArg::Fd(..))) => {
                let (res, _) = self.use_fd(call, d, fd, Io::None)?;
                if !empty_path {
                    self.mark_dir(res);
                }
                let name = &self.resources[res].name;
                name.starts_with('/').then(|| name.clone())
            }
            Some((d, fd @ FdArg::AtFdCwd(_))) => {
                self.use_fd(call, d, fd, Io::None);
                self.cwd(call.pid)
            }
            None => self.cwd(call.pid),
        }
    }

    /// Record an access by path (stat, unlink, ...), returning the resource
    fn path_access(
        &mut self,
        call: &Call,
        dirfd_arg: Option<usize>,
        path_arg: usize,
    ) -> Option<usize> {
        let path = parse_string_arg(call.arg(path_arg));
        let base = self.dir_base(call, dirfd_arg, path.is_some_and(str::is_empty));
        let path = path?;
        if path.is_empty() {
            // AT_EMPTY_PATH: the call is about the dirfd itself
            return None;
        }
        let name = resolve_path(base.as_deref(), path);
        let res = self.path_resource(&name, call.start_idx);
        self.access(call, res, None, None, Io::None);
        self.add_ref(call, Some(path_arg), res, None);
        Some(res)
    }

    // ----- fd creation and destruction -----

    fn open(&mut self, call: &Call, dirfd_arg: Option<usize>, path_arg: usize, flags_arg: usize) {
        let base = self.dir_base(call, dirfd_arg, false);
        let resolved =
            parse_string_arg(call.arg(path_arg)).map(|p| resolve_path(base.as_deref(), p));
        let flags = call.args.get(flags_arg).cloned();
        let is_dir = flags.as_deref().is_some_and(|f| f.contains("O_DIRECTORY"));

        if let Some(fd) = call.ret_fd() {
            let hint = if is_dir {
                ResourceKind::Directory
            } else {
                ResourceKind::File
            };
            let res = match (call.ret_annotation, &resolved) {
                (Some(annotation), _) => {
                    self.annotated_resource(annotation, hint, call.pid, fd, call.start_idx)
                }
                (None, Some(path)) => self.path_resource(path, call.start_idx),
                (None, None) => self.new_resource(
                    format!("{} [pid {}, fd {}]", call.name, call.pid, fd),
                    hint,
                    call.start_idx,
                    false,
                ),
            };
            if is_dir {
                self.mark_dir(res);
            }
            let cloexec = flags.as_deref().is_some_and(|f| f.contains("O_CLOEXEC"));
            let lt = self.new_lifetime(call, res, fd, flags, cloexec);
            self.access(call, res, Some(lt), Some(fd), Io::None);
            self.add_ref(call, Some(path_arg), res, Some(lt));
        } else if let Some(path) = resolved {
            let res = self.path_resource(&path, call.start_idx);
            if is_dir {
                self.mark_dir(res);
            }
            self.access(call, res, None, None, Io::None);
            self.add_ref(call, Some(path_arg), res, None);
        }
    }

    /// socket(), eventfd(), ...: a new resource whose fd is the return value
    fn create_from_ret(&mut self, call: &Call, kind: ResourceKind, label: &str) {
        let Some(fd) = call.ret_fd() else {
            return;
        };
        let res = match call.ret_annotation {
            Some(annotation) => {
                self.annotated_resource(annotation, kind, call.pid, fd, call.start_idx)
            }
            None => self.new_resource(
                format!("{} [pid {}, fd {}]", label, call.pid, fd),
                kind,
                call.start_idx,
                false,
            ),
        };
        let flags = match call.name {
            "socket" => call.args.get(1).cloned(),
            "accept4" | "eventfd2" | "timerfd_create" | "inotify_init1" | "memfd_create" => {
                call.args.last().cloned()
            }
            "epoll_create1" | "fanotify_init" | "userfaultfd" => call.args.first().cloned(),
            _ => None,
        };
        let cloexec = call.args.iter().any(|a| a.contains("CLOEXEC"));
        let lt = self.new_lifetime(call, res, fd, flags, cloexec);
        self.access(call, res, Some(lt), Some(fd), Io::None);
        self.add_ref(call, None, res, Some(lt));
    }

    /// pipe() and socketpair(): two fds returned through an array argument
    fn create_pair(&mut self, call: &Call, array_arg: usize, kind: ResourceKind) {
        if !call.ok() {
            return;
        }
        let fds = parse_fd_array(call.arg(array_arg));
        let fds: Vec<(i32, Option<&str>)> = fds
            .iter()
            .filter_map(|fd| match *fd {
                FdArg::Fd(fd, annotation) if fd >= 0 => Some((fd, annotation)),
                _ => None,
            })
            .collect();
        let [(fd0, ann0), (fd1, ann1)] = fds[..] else {
            return;
        };

        let res = match (kind, ann0, ann1) {
            (ResourceKind::Pipe, Some(ann), _) => {
                self.annotated_resource(ann, kind, call.pid, fd0, call.start_idx)
            }
            (_, Some(ann0), Some(ann1)) => {
                let name = format!("{} ↔ {}", ann0, ann1);
                let res = self.new_resource(name, kind, call.start_idx, false);
                // Let inherited fds with either annotation find this resource
                self.by_name.insert(ann0.to_string(), res);
                self.by_name.insert(ann1.to_string(), res);
                res
            }
            _ => self.new_resource(
                format!("{} [pid {}, fds {}, {}]", kind.label(), call.pid, fd0, fd1),
                kind,
                call.start_idx,
                false,
            ),
        };

        // pipe2(fds, flags) and socketpair(domain, type, protocol, fds)
        let flags = call
            .args
            .get(1)
            .filter(|f| f.as_str() != "0" && call.name != "pipe")
            .cloned();
        let cloexec = call.args.iter().any(|a| a.contains("CLOEXEC"));
        let ends: [(i32, Option<&str>); 2] = if kind == ResourceKind::Pipe {
            [(fd0, Some("read end")), (fd1, Some("write end"))]
        } else {
            [(fd0, None), (fd1, None)]
        };
        for (fd, end) in ends {
            let label = match (end, &flags) {
                (Some(end), Some(flags)) => Some(format!("{}, {}", end, flags)),
                (Some(end), None) => Some(end.to_string()),
                (None, flags) => flags.clone(),
            };
            let lt = self.new_lifetime(call, res, fd, label, cloexec);
            self.access(call, res, Some(lt), Some(fd), Io::None);
            self.add_ref(call, Some(array_arg), res, Some(lt));
        }
    }

    fn close(&mut self, call: &Call) {
        let Some((_, _)) = self.use_fd_arg(call, 0, Io::None) else {
            return;
        };
        // close() releases the fd even when it fails, except for EBADF
        if call.ret.is_none() {
            return;
        }
        if let Some(fd) = call.arg_fd(0) {
            let table = self.table_of(call.pid);
            if let Some(slot) = self.tables[table].fds.remove(&fd) {
                self.release(
                    slot.lifetime,
                    LifetimeEnd::Closed {
                        entry_idx: call.start_idx,
                    },
                );
            }
        }
    }

    fn close_range(&mut self, call: &Call) {
        if !call.ok() {
            return;
        }
        let parse = |s: &str| {
            if s.starts_with('~') {
                Some(i32::MAX)
            } else {
                s.parse::<u32>()
                    .ok()
                    .map(|v| i32::try_from(v).unwrap_or(i32::MAX))
            }
        };
        let (Some(first), Some(last)) = (parse(call.arg(0)), parse(call.arg(1))) else {
            return;
        };
        let set_cloexec = call.arg(2).contains("CLOSE_RANGE_CLOEXEC");
        let table = self.table_of(call.pid);
        let fds: Vec<(i32, Slot)> = self.tables[table]
            .fds
            .range(first..=last)
            .map(|(&fd, &slot)| (fd, slot))
            .collect();
        for (fd, slot) in fds {
            let (res, lt) = slot.lifetime;
            self.access(call, res, Some(lt), Some(fd), Io::None);
            self.add_ref(call, None, res, Some(lt));
            if set_cloexec {
                if let Some(slot) = self.tables[table].fds.get_mut(&fd) {
                    slot.cloexec = true;
                }
            } else {
                self.tables[table].fds.remove(&fd);
                self.release(
                    slot.lifetime,
                    LifetimeEnd::Closed {
                        entry_idx: call.start_idx,
                    },
                );
            }
        }
    }

    /// dup/dup2/dup3/fcntl(F_DUPFD): make `target` refer to the lifetime of argument 0
    fn dup(&mut self, call: &Call, target: Option<i32>, cloexec: bool) {
        let source = self.use_fd_arg(call, 0, Io::None);
        let (Some(source), Some(target)) = (source, target) else {
            return;
        };
        if call.arg_fd(0) == Some(target) {
            return;
        }

        let table = self.table_of(call.pid);
        // dup2 silently closes the target fd if it was open
        let target_is_arg = call.name == "dup2" || call.name == "dup3";
        let mut old = self.tables[table]
            .fds
            .remove(&target)
            .map(|slot| slot.lifetime);
        if old.is_none()
            && target_is_arg
            && let Some(FdArg::Fd(_, Some(annotation))) = parse_fd_arg(call.arg(1))
        {
            // With -y we know the target was open before the trace
            self.lookup_fd(call, target, Some(annotation));
            old = self.tables[table]
                .fds
                .remove(&target)
                .map(|slot| slot.lifetime);
        }
        if let Some(old) = old {
            let (res, lt) = old;
            self.access(call, res, Some(lt), Some(target), Io::None);
            if target_is_arg {
                self.add_ref(call, Some(1), res, Some(lt));
            }
            self.release(
                old,
                LifetimeEnd::Closed {
                    entry_idx: call.start_idx,
                },
            );
        } else if target_is_arg {
            self.add_ref(call, Some(1), source.0, Some(source.1));
        }

        let (res, lt) = source;
        let lifetime = &mut self.resources[res].lifetimes[lt];
        lifetime.open_slots += 1;
        let alias = FdAlias {
            pid: call.pid,
            fd: target,
        };
        if !lifetime.aliases.contains(&alias) {
            lifetime.aliases.push(alias);
        }
        self.tables[table].fds.insert(
            target,
            Slot {
                lifetime: source,
                cloexec,
            },
        );
    }

    fn fcntl(&mut self, call: &Call) {
        let cmd = call.arg(1);
        if cmd.starts_with("F_DUPFD") {
            self.dup(call, call.ret_fd(), cmd == "F_DUPFD_CLOEXEC");
            return;
        }
        self.use_fd_arg(call, 0, Io::None);
        if cmd == "F_SETFD"
            && call.ok()
            && let Some(fd) = call.arg_fd(0)
        {
            let table = self.table_of(call.pid);
            let cloexec = call.arg(2).contains("FD_CLOEXEC");
            if let Some(slot) = self.tables[table].fds.get_mut(&fd) {
                slot.cloexec = cloexec;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::StraceParser;
    use pretty_assertions::assert_eq;

    fn analyze(lines: &[&str]) -> (Vec<SyscallEntry>, FileAnalysis) {
        let entries = StraceParser::new()
            .parse_lines(lines.iter().map(|l| l.to_string()), false)
            .unwrap();
        let analysis = analyze_files(&entries);
        (entries, analysis)
    }

    fn find<'a>(analysis: &'a FileAnalysis, name: &str) -> &'a FileResource {
        analysis
            .resources
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "no resource {name:?} in {:?}",
                    analysis
                        .resources
                        .iter()
                        .map(|r| &r.name)
                        .collect::<Vec<_>>()
                )
            })
    }

    fn access_idxs(accesses: &[FileAccess]) -> Vec<usize> {
        accesses.iter().map(|a| a.entry_idx).collect()
    }

    fn aliases(lifetime: &FdLifetime) -> Vec<(u32, i32)> {
        lifetime.aliases.iter().map(|a| (a.pid, a.fd)).collect()
    }

    #[test]
    fn test_open_read_close() {
        let (_, analysis) = analyze(&[
            r#"100 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"#,
            r#"100 read(3, "root:x:0:0"..., 4096) = 1024"#,
            r#"100 read(3, "", 4096) = 0"#,
            r#"100 close(3) = 0"#,
        ]);
        assert_eq!(analysis.resources.len(), 1);
        let file = find(&analysis, "/etc/passwd");
        assert_eq!(file.kind, ResourceKind::File);
        assert_eq!(file.pids, vec![100]);
        assert_eq!(
            file.stats,
            AccessStats {
                calls: 4,
                errors: 0,
                bytes_read: 1024,
                bytes_written: 0
            }
        );
        let lifetime = &file.lifetimes[0];
        assert_eq!(lifetime.open_entry_idx, Some(0));
        assert_eq!(lifetime.flags.as_deref(), Some("O_RDONLY|O_CLOEXEC"));
        assert_eq!(access_idxs(&lifetime.accesses), vec![0, 1, 2, 3]);
        assert_eq!(lifetime.end, LifetimeEnd::Closed { entry_idx: 3 });

        assert_eq!(
            analysis.refs(1),
            &[ResourceRef {
                arg_idx: Some(0),
                resource: 0,
                lifetime: Some(0)
            }]
        );
        assert_eq!(
            analysis.refs(0),
            &[ResourceRef {
                arg_idx: Some(1),
                resource: 0,
                lifetime: Some(0)
            }]
        );
    }

    #[test]
    fn test_fd_reuse_and_failed_open() {
        let (_, analysis) = analyze(&[
            r#"1 openat(AT_FDCWD, "/a", O_RDONLY) = 3"#,
            r#"1 close(3) = 0"#,
            r#"1 openat(AT_FDCWD, "/missing", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
            r#"1 openat(AT_FDCWD, "/b", O_RDONLY) = 3"#,
            r#"1 read(3, "x", 1) = 1"#,
            r#"1 close(3) = 0"#,
            r#"1 close(3) = -1 EBADF (Bad file descriptor)"#,
        ]);
        let names: Vec<&str> = analysis.resources.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["/a", "/missing", "/b"]);
        let missing = find(&analysis, "/missing");
        assert!(missing.lifetimes.is_empty());
        assert_eq!(access_idxs(&missing.path_accesses), vec![2]);
        assert!(missing.all_failed());
        let b = find(&analysis, "/b");
        assert_eq!(access_idxs(&b.lifetimes[0].accesses), vec![3, 4, 5]);
        assert!(analysis.refs(6).is_empty());
    }

    #[test]
    fn test_dup2_and_fork_inheritance() {
        let (_, analysis) = analyze(&[
            r#"10 pipe2([3, 4], O_CLOEXEC) = 0"#,
            r#"10 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 11"#,
            r#"11 dup2(4, 1</dev/pts/0<char 136:0>>) = 1"#,
            r#"11 close(4) = 0"#,
            r#"11 close(3) = 0"#,
            r#"11 execve("/bin/echo", ["echo", "hi"], 0x7ffe /* 1 vars */) = 0"#,
            r#"11 write(1, "hi\n", 3) = 3"#,
            r#"11 +++ exited with 0 +++"#,
            r#"10 close(4) = 0"#,
            r#"10 read(3, "hi\n", 128) = 3"#,
        ]);
        let pipe = find(&analysis, "pipe [pid 10, fds 3, 4]");
        assert_eq!(pipe.kind, ResourceKind::Pipe);
        assert_eq!(pipe.pids, vec![10, 11]);
        assert_eq!(pipe.stats.bytes_read, 3);
        assert_eq!(pipe.stats.bytes_written, 3);

        let read_end = &pipe.lifetimes[0];
        assert_eq!(read_end.flags.as_deref(), Some("read end, O_CLOEXEC"));
        assert_eq!(aliases(read_end), vec![(10, 3), (11, 3)]);
        assert_eq!(read_end.end, LifetimeEnd::StillOpen);

        let write_end = &pipe.lifetimes[1];
        assert_eq!(aliases(write_end), vec![(10, 4), (11, 4), (11, 1)]);
        assert_eq!(access_idxs(&write_end.accesses), vec![0, 2, 3, 6, 8]);
        // fd 1 of the child was not close-on-exec, and survived until it exited
        assert_eq!(write_end.end, LifetimeEnd::Closed { entry_idx: 8 });

        // The child's fd 1 before dup2 was inherited from before the trace
        let tty = find(&analysis, "/dev/pts/0");
        assert_eq!(tty.kind, ResourceKind::Device);
        assert_eq!(tty.lifetimes[0].open_entry_idx, None);
        assert_eq!(tty.lifetimes[0].end, LifetimeEnd::Closed { entry_idx: 2 });

        let echo = find(&analysis, "/bin/echo");
        assert_eq!(access_idxs(&echo.path_accesses), vec![5]);
    }

    #[test]
    fn test_child_runs_before_fork_returns() {
        let (_, analysis) = analyze(&[
            r#"10 openat(AT_FDCWD, "/log", O_WRONLY) = 3"#,
            r#"10 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>"#,
            r#"11 write(3, "child", 5) = 5"#,
            r#"10 <... clone resumed>, child_tidptr=0x7f) = 11"#,
            r#"10 close(3) = 0"#,
            r#"11 +++ exited with 0 +++"#,
        ]);
        let log = find(&analysis, "/log");
        assert_eq!(log.lifetimes.len(), 1);
        let lifetime = &log.lifetimes[0];
        assert_eq!(aliases(lifetime), vec![(10, 3), (11, 3)]);
        assert_eq!(lifetime.stats.bytes_written, 5);
        assert_eq!(lifetime.end, LifetimeEnd::ProcessExit { entry_idx: 5 });
    }

    #[test]
    fn test_threads_share_fd_table() {
        let (_, analysis) = analyze(&[
            r#"10 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD, exit_signal=0}, 88) = 11"#,
            r#"11 openat(AT_FDCWD, "/data", O_RDONLY) = 5"#,
            r#"10 read(5, "abc", 3) = 3"#,
            r#"11 +++ exited with 0 +++"#,
            r#"10 close(5) = 0"#,
        ]);
        let data = find(&analysis, "/data");
        assert_eq!(aliases(&data.lifetimes[0]), vec![(11, 5)]);
        assert_eq!(access_idxs(&data.lifetimes[0].accesses), vec![1, 2, 4]);
        assert_eq!(data.lifetimes[0].end, LifetimeEnd::Closed { entry_idx: 4 });
    }

    #[test]
    fn test_yy_annotations() {
        let (_, analysis) = analyze(&[
            r#"8 openat(AT_FDCWD</tmp>, "x", O_RDONLY|O_CLOEXEC) = 4</tmp/x>"#,
            r#"8 fstat(4</tmp/x>, {st_mode=S_IFREG|0644, st_size=1, ...}) = 0"#,
            r#"8 ioctl(0</dev/null<char 1:3>>, TCGETS2, 0x7fff) = -1 ENOTTY (Inappropriate ioctl for device)"#,
            r#"8 pipe2([5<pipe:[99]>, 6<pipe:[99]>], 0) = 0"#,
            r#"8 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 7<UDP:[832764]>"#,
            r#"8 sendto(7<UDP:[127.0.0.1:5]>, "x", 1, 0, NULL, 0) = 1"#,
            r#"8 eventfd2(0, EFD_CLOEXEC) = 9<{eventfd-count=0, eventfd-id=271, eventfd-semaphore=0}>"#,
            r#"8 newfstatat(AT_FDCWD</tmp>, "sub/../y", 0x7fff, 0) = -1 ENOENT (No such file or directory)"#,
        ]);
        let names: Vec<(&str, ResourceKind)> = analysis
            .resources
            .iter()
            .map(|r| (r.name.as_str(), r.kind))
            .collect();
        assert_eq!(
            names,
            vec![
                ("/tmp/x", ResourceKind::File),
                ("/dev/null", ResourceKind::Device),
                ("pipe:[99]", ResourceKind::Pipe),
                ("UDP:[832764]", ResourceKind::Socket),
                ("eventfd:[271]", ResourceKind::EventFd),
                ("/tmp/y", ResourceKind::File),
            ]
        );
        let null = find(&analysis, "/dev/null");
        assert_eq!(null.lifetimes[0].open_entry_idx, None);
        assert_eq!(null.stats.errors, 1);
        let udp = find(&analysis, "UDP:[832764]");
        assert_eq!(udp.stats.bytes_written, 1);
        assert_eq!(
            udp.lifetimes[0].flags.as_deref(),
            Some("SOCK_DGRAM|SOCK_CLOEXEC")
        );
        assert_eq!(
            analysis.refs(4),
            &[ResourceRef {
                arg_idx: None,
                resource: 3,
                lifetime: Some(0)
            }]
        );
        assert_eq!(analysis.refs(3).len(), 2);
    }

    #[test]
    fn test_cwd_tracking() {
        let (_, analysis) = analyze(&[
            r#"1 chdir("/home/user") = 0"#,
            r#"1 openat(AT_FDCWD, "notes.txt", O_RDONLY) = 3"#,
            r#"1 openat(AT_FDCWD, "src", O_RDONLY|O_DIRECTORY) = 4"#,
            r#"1 openat(4, "main.rs", O_RDONLY) = 5"#,
            r#"1 fchdir(4) = 0"#,
            r#"1 stat("../x", 0x7fff) = -1 ENOENT (No such file or directory)"#,
        ]);
        let names: Vec<(&str, ResourceKind)> = analysis
            .resources
            .iter()
            .map(|r| (r.name.as_str(), r.kind))
            .collect();
        assert_eq!(
            names,
            vec![
                ("/home/user", ResourceKind::Directory),
                ("/home/user/notes.txt", ResourceKind::File),
                ("/home/user/src", ResourceKind::Directory),
                ("/home/user/src/main.rs", ResourceKind::File),
                ("/home/user/x", ResourceKind::File),
            ]
        );
        let src = find(&analysis, "/home/user/src");
        // opened, used as dirfd, then fchdir
        assert_eq!(access_idxs(&src.lifetimes[0].accesses), vec![2, 3, 4]);
    }

    #[test]
    fn test_cloexec_on_exec() {
        let (_, analysis) = analyze(&[
            r#"1 openat(AT_FDCWD, "/a", O_RDONLY|O_CLOEXEC) = 3"#,
            r#"1 openat(AT_FDCWD, "/b", O_RDONLY) = 4"#,
            r#"1 openat(AT_FDCWD, "/c", O_RDONLY) = 5"#,
            r#"1 fcntl(5, F_SETFD, FD_CLOEXEC) = 0"#,
            r#"1 fcntl(4, F_DUPFD_CLOEXEC, 10) = 10"#,
            r#"1 execve("/bin/true", ["true"], 0x7ffe /* 1 vars */) = 0"#,
            r#"1 +++ exited with 0 +++"#,
        ]);
        assert_eq!(
            find(&analysis, "/a").lifetimes[0].end,
            LifetimeEnd::CloseOnExec { entry_idx: 5 }
        );
        let b = &find(&analysis, "/b").lifetimes[0];
        assert_eq!(aliases(b), vec![(1, 4), (1, 10)]);
        assert_eq!(b.end, LifetimeEnd::ProcessExit { entry_idx: 6 });
        assert_eq!(
            find(&analysis, "/c").lifetimes[0].end,
            LifetimeEnd::CloseOnExec { entry_idx: 5 }
        );
    }

    #[test]
    fn test_poll_and_select() {
        let (_, analysis) = analyze(&[
            r#"1 pipe([3, 4]) = 0"#,
            r#"1 poll([{fd=3, events=POLLIN}, {fd=4, events=POLLOUT}], 2, -1) = 1 ([{fd=4, revents=POLLOUT}])"#,
            r#"1 select(5, [3], [4], NULL, NULL) = 1 (out [4])"#,
        ]);
        let pipe = &analysis.resources[0];
        assert_eq!(pipe.lifetimes[0].flags.as_deref(), Some("read end"));
        assert_eq!(access_idxs(&pipe.lifetimes[0].accesses), vec![0, 1, 2]);
        assert_eq!(access_idxs(&pipe.lifetimes[1].accesses), vec![0, 1, 2]);
        assert_eq!(pipe.stats.calls, 3);
        let arg_idxs: Vec<Option<usize>> = analysis.refs(2).iter().map(|r| r.arg_idx).collect();
        assert_eq!(arg_idxs, vec![Some(1), Some(2)]);
    }

    #[test]
    fn test_split_syscall_refs() {
        let (_, analysis) = analyze(&[
            r#"1 openat(AT_FDCWD, "/a", O_RDONLY) = 3"#,
            r#"1 read(3, <unfinished ...>"#,
            r#"2 getpid() = 2"#,
            r#"1 <... read resumed>"abc", 10) = 3"#,
            r#"1 pipe2(<unfinished ...>"#,
            r#"1 <... pipe2 resumed>[4, 5], 0) = 0"#,
        ]);
        let a = find(&analysis, "/a");
        // The access points to the first half, the refs to the half with the argument
        assert_eq!(access_idxs(&a.lifetimes[0].accesses), vec![0, 1]);
        assert_eq!(a.stats.bytes_read, 3);
        assert_eq!(analysis.refs(1)[0].arg_idx, Some(0));
        assert!(analysis.refs(3).is_empty());
        let pipe = &analysis.resources[1];
        assert_eq!(access_idxs(&pipe.lifetimes[0].accesses), vec![4]);
        assert_eq!(analysis.refs(5)[0].arg_idx, Some(0));
    }
}
