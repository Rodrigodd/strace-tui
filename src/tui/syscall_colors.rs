use ratatui::style::Color;

/// Returns the color for a syscall based on its category
pub fn syscall_category_color(name: &str) -> Color {
    match name {
        // File I/O - Blue
        "read" | "write" | "pread" | "pwrite" | "pread64" | "pwrite64" | "readv" | "writev"
        | "preadv" | "pwritev" | "open" | "openat" | "openat2" | "creat" | "close" | "dup"
        | "dup2" | "dup3" | "lseek" | "llseek" | "_llseek" | "fcntl" | "ioctl" | "fstat"
        | "stat" | "lstat" | "fstatat" | "newfstatat" | "statx" | "ftruncate" | "truncate"
        | "fsync" | "fdatasync" | "sync" | "syncfs" | "access" | "faccessat" | "faccessat2" => {
            Color::Blue
        }

        // Process/Thread Control - Magenta
        "fork" | "vfork" | "clone" | "clone3" | "execve" | "execveat" | "exit" | "exit_group"
        | "wait4" | "waitid" | "waitpid" | "kill" | "tkill" | "tgkill" | "getpid" | "gettid"
        | "getppid" | "getpgid" | "getsid" | "setpgid" | "setsid" | "ptrace" | "prctl" => {
            Color::Magenta
        }

        // Memory Management - Cyan
        "mmap" | "mmap2" | "munmap" | "mremap" | "msync" | "mprotect" | "madvise" | "mlock"
        | "mlock2" | "munlock" | "mlockall" | "munlockall" | "brk" | "sbrk" | "memfd_create"
        | "userfaultfd" | "remap_file_pages" => Color::Cyan,

        // Network/IPC - Green
        "socket" | "bind" | "listen" | "accept" | "accept4" | "connect" | "send" | "sendto"
        | "sendmsg" | "sendmmsg" | "recv" | "recvfrom" | "recvmsg" | "recvmmsg" | "shutdown"
        | "getsockopt" | "setsockopt" | "pipe" | "pipe2" | "socketpair" | "getpeername"
        | "getsockname" => Color::Green,

        // Filesystem Operations - Yellow
        "mkdir" | "mkdirat" | "rmdir" | "unlink" | "unlinkat" | "rename" | "renameat"
        | "renameat2" | "link" | "linkat" | "symlink" | "symlinkat" | "readlink" | "readlinkat"
        | "chmod" | "fchmod" | "fchmodat" | "chown" | "fchown" | "lchown" | "fchownat"
        | "chdir" | "fchdir" | "getcwd" | "mount" | "umount" | "umount2" | "chroot"
        | "pivot_root" | "getdents" | "getdents64" | "statfs" | "fstatfs" => Color::Yellow,

        // Time/Timers - LightBlue
        "gettimeofday" | "settimeofday" | "clock_gettime" | "clock_settime" | "clock_getres"
        | "clock_nanosleep" | "time" | "stime" | "nanosleep" | "timer_create" | "timer_settime"
        | "timer_gettime" | "timer_delete" | "timer_getoverrun" | "alarm" | "setitimer"
        | "getitimer" => Color::LightBlue,

        // Signal Handling - LightRed
        "signal" | "sigaction" | "sigreturn" | "rt_sigaction" | "rt_sigreturn" | "sigprocmask"
        | "rt_sigprocmask" | "sigpending" | "rt_sigpending" | "sigsuspend" | "rt_sigsuspend"
        | "signalfd" | "signalfd4" => Color::LightRed,

        // Security/Permissions - LightMagenta
        "setuid" | "setgid" | "setreuid" | "setregid" | "setresuid" | "setresgid" | "getuid"
        | "getgid" | "geteuid" | "getegid" | "capget" | "capset" | "setgroups" | "getgroups"
        | "seccomp" | "keyctl" | "add_key" | "request_key" => Color::LightMagenta,

        // Polling/Events - LightGreen
        "select" | "pselect6" | "poll" | "ppoll" | "epoll_create" | "epoll_create1"
        | "epoll_ctl" | "epoll_wait" | "epoll_pwait" | "inotify_init" | "inotify_init1"
        | "inotify_add_watch" | "inotify_rm_watch" | "eventfd" | "eventfd2" | "timerfd_create"
        | "timerfd_settime" | "timerfd_gettime" => Color::LightGreen,

        // Resource Limits - LightYellow
        "getrlimit" | "setrlimit" | "prlimit64" | "getrusage" | "getpriority" | "setpriority"
        | "nice" | "sched_setscheduler" | "sched_getscheduler" | "sched_setparam"
        | "sched_getparam" | "sched_setaffinity" | "sched_getaffinity" | "sched_yield" => {
            Color::LightYellow
        }

        // Default - White
        _ => Color::White,
    }
}
