package seccompprofile

// AlwaysAllowed is the list of the syscalls that do not need to be traced.
// For the performance reason, FD operations like read and write are always allowed.
//
// https://filippo.io/linux-syscall-table/
var AlwaysAllowed = []string{
	// ===== 000 =====
	"read",
	"write",
	"close",
	"lstat",
	"poll",
	"lseek",
	"mmap",
	"mprotect",
	"munmap",
	"brk",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"pread64",
	"pwrite64",
	"readv",
	"writev",
	"access",
	"pipe",
	"select",
	"sched_yield",
	"mremap",
	"msync",
	"mincore",
	"madvise",
	"dup",
	"dup2",
	"pause",
	"nanosleep",
	"getitimer",
	"alarm",
	"setitimer",
	"getpid",
	"sendfile",
	"clone",
	"exit",
	"wait4",
	"uname",
	"fsync",
	"ftruncate",
	"getdents",
	"getcwd",
	"chdir",
	"fchdir",
	"gettimeofday",
	"getrlimit",
	"getrusage",
	"sysinfo",
	// ===== 100 =====
	"times",
	"getuid",
	"syslog",
	"getgid",
	"setuid",
	"setgid",
	"geteuid",
	"getegid",
	"setpgid",
	"getppid",
	"getpgrp",
	"setsid",
	"setreuid",
	"setregid",
	"getgroups",
	"setgroups",
	"setresuid",
	"getresuid",
	"setresgid",
	"getresgid",
	"getpgid",
	"setfsuid",
	"setfsgid",
	"getsid",
	"capget",
	"capset",
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"sigaltstack",
	"utime",
	"ustat",
	"statfs",
	"fstatfs",
	"sysfs",
	"getpriority",
	"setpriority",
	"sched_setparam",
	"sched_getparam",
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_rr_get_interval",
	"mlock",
	"munlock",
	"mlockall",
	"munlockall",
	"sync",
	"acct",
	"gettid",
	"readahead",
	// ===== 200 =====
	"tkill",
	"time",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",
	"set_thread_area",
	"get_thread_area",
	"epoll_create",
	"timer_create",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"exit_group",
	"epoll_wait",
	"epoll_ctl",
	"tgkill",
	"newfstatat",
	"faccessat",
	"epoll_pwait",
	"eventfd",
	"eventfd2",
	"epoll_create1",
	"dup3",
	"pipe2",
	"preadv",
	"pwritev",
	// ===== 300 =====
	"sched_setattr",
	"sched_getattr",
	"seccomp",
	"getrandom",
	"memfd_create",
	"preadv2",
	"pwritev2",
	// ===== 400 =====
	"clone3",
	"faccessat2",
	"epoll_pwait2",
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"memfd_secret",
	"futex_waitv",
	"futex_wake",
	"futex_wait",
	"futex_requeue",
}

// TODO: more
