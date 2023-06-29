#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define fatal(msg)                                                                                                                                             \
	fprintf(stderr, "%s:%d: error in function %s: ", __FILE__, __LINE__, __func__);                                                                            \
	perror(msg);                                                                                                                                               \
	exit(1);

pid_t child_pid;

void extract_str(char *buf, size_t bufsz, unsigned long long address) {
	size_t i = 0;
	while (i < bufsz) {
		unsigned long long data = ptrace(PTRACE_PEEKDATA, child_pid, address + i, NULL);
		if (data != -1 && errno) {
			fatal("failed to read memory");
		}
		memcpy(buf + i, &data, sizeof(data));
		if (memchr(&data, 0, sizeof(data)) != NULL)
			return;
		i += sizeof(data);
	}
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
		return 1;
	}

	FILE *sink = stderr;

	child_pid = fork();
	if (child_pid == -1) {
		fatal("failed to fork a child");
	} else if (child_pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			fatal("failed to trace the child");
		}
		execvp(argv[1], argv + 1);
		fatal("failed to execute the child");
	} else {
		int status;

		while (waitpid(child_pid, &status, 0) && !WIFEXITED(status)) {
			struct user_regs_struct regs;

			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

			switch (regs.orig_rax) {

					// case SYS_read: { fprintf(sink, "read\n"); } break;
					// case SYS_write: { fprintf(sink, "write\n"); } break;
					// case SYS_open: { fprintf(sink, "open\n"); } break;
					// case SYS_close: { fprintf(sink, "close\n"); } break;
					// case SYS_stat: { fprintf(sink, "stat\n"); } break;
					// case SYS_fstat: { fprintf(sink, "fstat\n"); } break;
					// case SYS_lstat: { fprintf(sink, "lstat\n"); } break;
					// case SYS_poll: { fprintf(sink, "poll\n"); } break;
					// case SYS_lseek: { fprintf(sink, "lseek\n"); } break;
					// case SYS_mmap: { fprintf(sink, "mmap\n"); } break;
					// case SYS_mprotect: { fprintf(sink, "mprotect\n"); } break;
					// case SYS_munmap: { fprintf(sink, "munmap\n"); } break;
					// case SYS_brk: { fprintf(sink, "brk\n"); } break;
					// case SYS_rt_sigaction: { fprintf(sink, "rt_sigaction\n"); } break;
					// case SYS_rt_sigprocmask: { fprintf(sink, "rt_sigprocmask\n"); } break;
					// case SYS_rt_sigreturn: { fprintf(sink, "rt_sigreturn\n"); } break;
					// case SYS_ioctl: { fprintf(sink, "ioctl\n"); } break;
					// case SYS_pread64: { fprintf(sink, "pread64\n"); } break;
					// case SYS_pwrite64: { fprintf(sink, "pwrite64\n"); } break;
					// case SYS_readv: { fprintf(sink, "readv\n"); } break;
					// case SYS_writev: { fprintf(sink, "writev\n"); } break;
					// case SYS_access: { fprintf(sink, "access\n"); } break;
					// case SYS_pipe: { fprintf(sink, "pipe\n"); } break;
					// case SYS_select: { fprintf(sink, "select\n"); } break;
					// case SYS_sched_yield: { fprintf(sink, "sched_yield\n"); } break;
					// case SYS_mremap: { fprintf(sink, "mremap\n"); } break;
					// case SYS_msync: { fprintf(sink, "msync\n"); } break;
					// case SYS_mincore: { fprintf(sink, "mincore\n"); } break;
					// case SYS_madvise: { fprintf(sink, "madvise\n"); } break;
					// case SYS_shmget: { fprintf(sink, "shmget\n"); } break;
					// case SYS_shmat: { fprintf(sink, "shmat\n"); } break;
					// case SYS_shmctl: { fprintf(sink, "shmctl\n"); } break;
					// case SYS_dup: { fprintf(sink, "dup\n"); } break;
					// case SYS_dup2: { fprintf(sink, "dup2\n"); } break;
					// case SYS_pause: { fprintf(sink, "pause\n"); } break;
					// case SYS_nanosleep: { fprintf(sink, "nanosleep\n"); } break;
					// case SYS_getitimer: { fprintf(sink, "getitimer\n"); } break;
					// case SYS_alarm: { fprintf(sink, "alarm\n"); } break;
					// case SYS_setitimer: { fprintf(sink, "setitimer\n"); } break;
					// case SYS_getpid: { fprintf(sink, "getpid\n"); } break;
					// case SYS_sendfile: { fprintf(sink, "sendfile\n"); } break;
					// case SYS_socket: { fprintf(sink, "socket\n"); } break;
					// case SYS_connect: { fprintf(sink, "connect\n"); } break;
					// case SYS_accept: { fprintf(sink, "accept\n"); } break;
					// case SYS_sendto: { fprintf(sink, "sendto\n"); } break;
					// case SYS_recvfrom: { fprintf(sink, "recvfrom\n"); } break;
					// case SYS_sendmsg: { fprintf(sink, "sendmsg\n"); } break;
					// case SYS_recvmsg: { fprintf(sink, "recvmsg\n"); } break;
					// case SYS_shutdown: { fprintf(sink, "shutdown\n"); } break;
					// case SYS_bind: { fprintf(sink, "bind\n"); } break;
					// case SYS_listen: { fprintf(sink, "listen\n"); } break;
					// case SYS_getsockname: { fprintf(sink, "getsockname\n"); } break;
					// case SYS_getpeername: { fprintf(sink, "getpeername\n"); } break;
					// case SYS_socketpair: { fprintf(sink, "socketpair\n"); } break;
					// case SYS_setsockopt: { fprintf(sink, "setsockopt\n"); } break;
					// case SYS_getsockopt: { fprintf(sink, "getsockopt\n"); } break;
					// case SYS_clone: { fprintf(sink, "clone\n"); } break;
					// case SYS_fork: { fprintf(sink, "fork\n"); } break;
					// case SYS_vfork: { fprintf(sink, "vfork\n"); } break;
					// case SYS_execve: { fprintf(sink, "execve\n"); } break;
					// case SYS_exit: { fprintf(sink, "exit\n"); } break;
					// case SYS_wait4: { fprintf(sink, "wait4\n"); } break;
					// case SYS_kill: { fprintf(sink, "kill\n"); } break;
					// case SYS_uname: { fprintf(sink, "uname\n"); } break;
					// case SYS_semget: { fprintf(sink, "semget\n"); } break;
					// case SYS_semop: { fprintf(sink, "semop\n"); } break;
					// case SYS_semctl: { fprintf(sink, "semctl\n"); } break;
					// case SYS_shmdt: { fprintf(sink, "shmdt\n"); } break;
					// case SYS_msgget: { fprintf(sink, "msgget\n"); } break;
					// case SYS_msgsnd: { fprintf(sink, "msgsnd\n"); } break;
					// case SYS_msgrcv: { fprintf(sink, "msgrcv\n"); } break;
					// case SYS_msgctl: { fprintf(sink, "msgctl\n"); } break;
					// case SYS_fcntl: { fprintf(sink, "fcntl\n"); } break;
					// case SYS_flock: { fprintf(sink, "flock\n"); } break;
					// case SYS_fsync: { fprintf(sink, "fsync\n"); } break;
					// case SYS_fdatasync: { fprintf(sink, "fdatasync\n"); } break;
					// case SYS_truncate: { fprintf(sink, "truncate\n"); } break;
					// case SYS_ftruncate: { fprintf(sink, "ftruncate\n"); } break;
					// case SYS_getdents: { fprintf(sink, "getdents\n"); } break;
					// case SYS_getcwd: { fprintf(sink, "getcwd\n"); } break;
					// case SYS_chdir: { fprintf(sink, "chdir\n"); } break;
					// case SYS_fchdir: { fprintf(sink, "fchdir\n"); } break;
					// case SYS_rename: { fprintf(sink, "rename\n"); } break;
					// case SYS_mkdir: { fprintf(sink, "mkdir\n"); } break;
					// case SYS_rmdir: { fprintf(sink, "rmdir\n"); } break;
					// case SYS_creat: { fprintf(sink, "creat\n"); } break;
					// case SYS_link: { fprintf(sink, "link\n"); } break;
					// case SYS_unlink: { fprintf(sink, "unlink\n"); } break;
					// case SYS_symlink: { fprintf(sink, "symlink\n"); } break;
					// case SYS_readlink: { fprintf(sink, "readlink\n"); } break;
					// case SYS_chmod: { fprintf(sink, "chmod\n"); } break;
					// case SYS_fchmod: { fprintf(sink, "fchmod\n"); } break;
					// case SYS_chown: { fprintf(sink, "chown\n"); } break;
					// case SYS_fchown: { fprintf(sink, "fchown\n"); } break;
					// case SYS_lchown: { fprintf(sink, "lchown\n"); } break;
					// case SYS_umask: { fprintf(sink, "umask\n"); } break;
					// case SYS_gettimeofday: { fprintf(sink, "gettimeofday\n"); } break;
					// case SYS_getrlimit: { fprintf(sink, "getrlimit\n"); } break;
					// case SYS_getrusage: { fprintf(sink, "getrusage\n"); } break;
					// case SYS_sysinfo: { fprintf(sink, "sysinfo\n"); } break;
					// case SYS_times: { fprintf(sink, "times\n"); } break;
					// case SYS_ptrace: { fprintf(sink, "ptrace\n"); } break;
					// case SYS_getuid: { fprintf(sink, "getuid\n"); } break;
					// case SYS_syslog: { fprintf(sink, "syslog\n"); } break;
					// case SYS_getgid: { fprintf(sink, "getgid\n"); } break;
					// case SYS_setuid: { fprintf(sink, "setuid\n"); } break;
					// case SYS_setgid: { fprintf(sink, "setgid\n"); } break;
					// case SYS_geteuid: { fprintf(sink, "geteuid\n"); } break;
					// case SYS_getegid: { fprintf(sink, "getegid\n"); } break;
					// case SYS_setpgid: { fprintf(sink, "setpgid\n"); } break;
					// case SYS_getppid: { fprintf(sink, "getppid\n"); } break;
					// case SYS_getpgrp: { fprintf(sink, "getpgrp\n"); } break;
					// case SYS_setsid: { fprintf(sink, "setsid\n"); } break;
					// case SYS_setreuid: { fprintf(sink, "setreuid\n"); } break;
					// case SYS_setregid: { fprintf(sink, "setregid\n"); } break;
					// case SYS_getgroups: { fprintf(sink, "getgroups\n"); } break;
					// case SYS_setgroups: { fprintf(sink, "setgroups\n"); } break;
					// case SYS_setresuid: { fprintf(sink, "setresuid\n"); } break;
					// case SYS_getresuid: { fprintf(sink, "getresuid\n"); } break;
					// case SYS_setresgid: { fprintf(sink, "setresgid\n"); } break;
					// case SYS_getresgid: { fprintf(sink, "getresgid\n"); } break;
					// case SYS_getpgid: { fprintf(sink, "getpgid\n"); } break;
					// case SYS_setfsuid: { fprintf(sink, "setfsuid\n"); } break;
					// case SYS_setfsgid: { fprintf(sink, "setfsgid\n"); } break;
					// case SYS_getsid: { fprintf(sink, "getsid\n"); } break;
					// case SYS_capget: { fprintf(sink, "capget\n"); } break;
					// case SYS_capset: { fprintf(sink, "capset\n"); } break;
					// case SYS_rt_sigpending: { fprintf(sink, "rt_sigpending\n"); } break;
					// case SYS_rt_sigtimedwait: { fprintf(sink, "rt_sigtimedwait\n"); } break;
					// case SYS_rt_sigqueueinfo: { fprintf(sink, "rt_sigqueueinfo\n"); } break;
					// case SYS_rt_sigsuspend: { fprintf(sink, "rt_sigsuspend\n"); } break;
					// case SYS_sigaltstack: { fprintf(sink, "sigaltstack\n"); } break;
					// case SYS_utime: { fprintf(sink, "utime\n"); } break;
					// case SYS_mknod: { fprintf(sink, "mknod\n"); } break;
					// case SYS_uselib: { fprintf(sink, "uselib\n"); } break;
					// case SYS_personality: { fprintf(sink, "personality\n"); } break;
					// case SYS_ustat: { fprintf(sink, "ustat\n"); } break;
					// case SYS_statfs: { fprintf(sink, "statfs\n"); } break;
					// case SYS_fstatfs: { fprintf(sink, "fstatfs\n"); } break;
					// case SYS_sysfs: { fprintf(sink, "sysfs\n"); } break;
					// case SYS_getpriority: { fprintf(sink, "getpriority\n"); } break;
					// case SYS_setpriority: { fprintf(sink, "setpriority\n"); } break;
					// case SYS_sched_setparam: { fprintf(sink, "sched_setparam\n"); } break;
					// case SYS_sched_getparam: { fprintf(sink, "sched_getparam\n"); } break;
					// case SYS_sched_setscheduler: { fprintf(sink, "sched_setscheduler\n"); } break;
					// case SYS_sched_getscheduler: { fprintf(sink, "sched_getscheduler\n"); } break;
					// case SYS_sched_get_priority_max: { fprintf(sink, "sched_get_priority_max\n"); } break;
					// case SYS_sched_get_priority_min: { fprintf(sink, "sched_get_priority_min\n"); } break;
					// case SYS_sched_rr_get_interval: { fprintf(sink, "sched_rr_get_interval\n"); } break;
					// case SYS_mlock: { fprintf(sink, "mlock\n"); } break;
					// case SYS_munlock: { fprintf(sink, "munlock\n"); } break;
					// case SYS_mlockall: { fprintf(sink, "mlockall\n"); } break;
					// case SYS_munlockall: { fprintf(sink, "munlockall\n"); } break;
					// case SYS_vhangup: { fprintf(sink, "vhangup\n"); } break;
					// case SYS_modify_ldt: { fprintf(sink, "modify_ldt\n"); } break;
					// case SYS_pivot_root: { fprintf(sink, "pivot_root\n"); } break;
					// case SYS__sysctl: { fprintf(sink, "_sysctl\n"); } break;
					// case SYS_prctl: { fprintf(sink, "prctl\n"); } break;
					// case SYS_arch_prctl: { fprintf(sink, "arch_prctl\n"); } break;
					// case SYS_adjtimex: { fprintf(sink, "adjtimex\n"); } break;
					// case SYS_setrlimit: { fprintf(sink, "setrlimit\n"); } break;
					// case SYS_chroot: { fprintf(sink, "chroot\n"); } break;
					// case SYS_sync: { fprintf(sink, "sync\n"); } break;
					// case SYS_acct: { fprintf(sink, "acct\n"); } break;
					// case SYS_settimeofday: { fprintf(sink, "settimeofday\n"); } break;
					// case SYS_mount: { fprintf(sink, "mount\n"); } break;
					// case SYS_umount2: { fprintf(sink, "umount2\n"); } break;
					// case SYS_swapon: { fprintf(sink, "swapon\n"); } break;
					// case SYS_swapoff: { fprintf(sink, "swapoff\n"); } break;
					// case SYS_reboot: { fprintf(sink, "reboot\n"); } break;
					// case SYS_sethostname: { fprintf(sink, "sethostname\n"); } break;
					// case SYS_setdomainname: { fprintf(sink, "setdomainname\n"); } break;
					// case SYS_iopl: { fprintf(sink, "iopl\n"); } break;
					// case SYS_ioperm: { fprintf(sink, "ioperm\n"); } break;
					// case SYS_create_module: { fprintf(sink, "create_module\n"); } break;
					// case SYS_init_module: { fprintf(sink, "init_module\n"); } break;
					// case SYS_delete_module: { fprintf(sink, "delete_module\n"); } break;
					// case SYS_get_kernel_syms: { fprintf(sink, "get_kernel_syms\n"); } break;
					// case SYS_query_module: { fprintf(sink, "query_module\n"); } break;
					// case SYS_quotactl: { fprintf(sink, "quotactl\n"); } break;
					// case SYS_nfsservctl: { fprintf(sink, "nfsservctl\n"); } break;
					// case SYS_getpmsg: { fprintf(sink, "getpmsg\n"); } break;
					// case SYS_putpmsg: { fprintf(sink, "putpmsg\n"); } break;
					// case SYS_afs_syscall: { fprintf(sink, "afs_syscall\n"); } break;
					// case SYS_tuxcall: { fprintf(sink, "tuxcall\n"); } break;
					// case SYS_security: { fprintf(sink, "security\n"); } break;
					// case SYS_gettid: { fprintf(sink, "gettid\n"); } break;
					// case SYS_readahead: { fprintf(sink, "readahead\n"); } break;
					// case SYS_setxattr: { fprintf(sink, "setxattr\n"); } break;
					// case SYS_lsetxattr: { fprintf(sink, "lsetxattr\n"); } break;
					// case SYS_fsetxattr: { fprintf(sink, "fsetxattr\n"); } break;
					// case SYS_getxattr: { fprintf(sink, "getxattr\n"); } break;
					// case SYS_lgetxattr: { fprintf(sink, "lgetxattr\n"); } break;
					// case SYS_fgetxattr: { fprintf(sink, "fgetxattr\n"); } break;
					// case SYS_listxattr: { fprintf(sink, "listxattr\n"); } break;
					// case SYS_llistxattr: { fprintf(sink, "llistxattr\n"); } break;
					// case SYS_flistxattr: { fprintf(sink, "flistxattr\n"); } break;
					// case SYS_removexattr: { fprintf(sink, "removexattr\n"); } break;
					// case SYS_lremovexattr: { fprintf(sink, "lremovexattr\n"); } break;
					// case SYS_fremovexattr: { fprintf(sink, "fremovexattr\n"); } break;
					// case SYS_tkill: { fprintf(sink, "tkill\n"); } break;
					// case SYS_time: { fprintf(sink, "time\n"); } break;
					// case SYS_futex: { fprintf(sink, "futex\n"); } break;
					// case SYS_sched_setaffinity: { fprintf(sink, "sched_setaffinity\n"); } break;
					// case SYS_sched_getaffinity: { fprintf(sink, "sched_getaffinity\n"); } break;
					// case SYS_set_thread_area: { fprintf(sink, "set_thread_area\n"); } break;
					// case SYS_io_setup: { fprintf(sink, "io_setup\n"); } break;
					// case SYS_io_destroy: { fprintf(sink, "io_destroy\n"); } break;
					// case SYS_io_getevents: { fprintf(sink, "io_getevents\n"); } break;
					// case SYS_io_submit: { fprintf(sink, "io_submit\n"); } break;
					// case SYS_io_cancel: { fprintf(sink, "io_cancel\n"); } break;
					// case SYS_get_thread_area: { fprintf(sink, "get_thread_area\n"); } break;
					// case SYS_lookup_dcookie: { fprintf(sink, "lookup_dcookie\n"); } break;
					// case SYS_epoll_create: { fprintf(sink, "epoll_create\n"); } break;
					// case SYS_epoll_ctl_old: { fprintf(sink, "epoll_ctl_old\n"); } break;
					// case SYS_epoll_wait_old: { fprintf(sink, "epoll_wait_old\n"); } break;
					// case SYS_remap_file_pages: { fprintf(sink, "remap_file_pages\n"); } break;
					// case SYS_getdents64: { fprintf(sink, "getdents64\n"); } break;
					// case SYS_set_tid_address: { fprintf(sink, "set_tid_address\n"); } break;
					// case SYS_restart_syscall: { fprintf(sink, "restart_syscall\n"); } break;
					// case SYS_semtimedop: { fprintf(sink, "semtimedop\n"); } break;
					// case SYS_fadvise64: { fprintf(sink, "fadvise64\n"); } break;
					// case SYS_timer_create: { fprintf(sink, "timer_create\n"); } break;
					// case SYS_timer_settime: { fprintf(sink, "timer_settime\n"); } break;
					// case SYS_timer_gettime: { fprintf(sink, "timer_gettime\n"); } break;
					// case SYS_timer_getoverrun: { fprintf(sink, "timer_getoverrun\n"); } break;
					// case SYS_timer_delete: { fprintf(sink, "timer_delete\n"); } break;
					// case SYS_clock_settime: { fprintf(sink, "clock_settime\n"); } break;
					// case SYS_clock_gettime: { fprintf(sink, "clock_gettime\n"); } break;
					// case SYS_clock_getres: { fprintf(sink, "clock_getres\n"); } break;
					// case SYS_clock_nanosleep: { fprintf(sink, "clock_nanosleep\n"); } break;
					// case SYS_exit_group: { fprintf(sink, "exit_group\n"); } break;
					// case SYS_epoll_wait: { fprintf(sink, "epoll_wait\n"); } break;
					// case SYS_epoll_ctl: { fprintf(sink, "epoll_ctl\n"); } break;
					// case SYS_tgkill: { fprintf(sink, "tgkill\n"); } break;
					// case SYS_utimes: { fprintf(sink, "utimes\n"); } break;
					// case SYS_vserver: { fprintf(sink, "vserver\n"); } break;
					// case SYS_mbind: { fprintf(sink, "mbind\n"); } break;
					// case SYS_set_mempolicy: { fprintf(sink, "set_mempolicy\n"); } break;
					// case SYS_get_mempolicy: { fprintf(sink, "get_mempolicy\n"); } break;
					// case SYS_mq_open: { fprintf(sink, "mq_open\n"); } break;
					// case SYS_mq_unlink: { fprintf(sink, "mq_unlink\n"); } break;
					// case SYS_mq_timedsend: { fprintf(sink, "mq_timedsend\n"); } break;
					// case SYS_mq_timedreceive: { fprintf(sink, "mq_timedreceive\n"); } break;
					// case SYS_mq_notify: { fprintf(sink, "mq_notify\n"); } break;
					// case SYS_mq_getsetattr: { fprintf(sink, "mq_getsetattr\n"); } break;
					// case SYS_kexec_load: { fprintf(sink, "kexec_load\n"); } break;
					// case SYS_waitid: { fprintf(sink, "waitid\n"); } break;
					// case SYS_add_key: { fprintf(sink, "add_key\n"); } break;
					// case SYS_request_key: { fprintf(sink, "request_key\n"); } break;
					// case SYS_keyctl: { fprintf(sink, "keyctl\n"); } break;
					// case SYS_ioprio_set: { fprintf(sink, "ioprio_set\n"); } break;
					// case SYS_ioprio_get: { fprintf(sink, "ioprio_get\n"); } break;
					// case SYS_inotify_init: { fprintf(sink, "inotify_init\n"); } break;
					// case SYS_inotify_add_watch: { fprintf(sink, "inotify_add_watch\n"); } break;
					// case SYS_inotify_rm_watch: { fprintf(sink, "inotify_rm_watch\n"); } break;
					// case SYS_migrate_pages: { fprintf(sink, "migrate_pages\n"); } break;
				case SYS_openat: {
					char filename[PATH_MAX] = {0};

					fprintf(sink, "openat: filename=\"%s\"\n", (extract_str(filename, sizeof(filename), regs.rsi), filename));
				} break;
					// case SYS_mkdirat: { fprintf(sink, "mkdirat\n"); } break;
					// case SYS_mknodat: { fprintf(sink, "mknodat\n"); } break;
					// case SYS_fchownat: { fprintf(sink, "fchownat\n"); } break;
					// case SYS_futimesat: { fprintf(sink, "futimesat\n"); } break;
					// case SYS_newfstatat: { fprintf(sink, "newfstatat\n"); } break;
					// case SYS_unlinkat: { fprintf(sink, "unlinkat\n"); } break;
					// case SYS_renameat: { fprintf(sink, "renameat\n"); } break;
					// case SYS_linkat: { fprintf(sink, "linkat\n"); } break;
					// case SYS_symlinkat: { fprintf(sink, "symlinkat\n"); } break;
					// case SYS_readlinkat: { fprintf(sink, "readlinkat\n"); } break;
					// case SYS_fchmodat: { fprintf(sink, "fchmodat\n"); } break;
					// case SYS_faccessat: { fprintf(sink, "faccessat\n"); } break;
					// case SYS_pselect6: { fprintf(sink, "pselect6\n"); } break;
					// case SYS_ppoll: { fprintf(sink, "ppoll\n"); } break;
					// case SYS_unshare: { fprintf(sink, "unshare\n"); } break;
					// case SYS_set_robust_list: { fprintf(sink, "set_robust_list\n"); } break;
					// case SYS_get_robust_list: { fprintf(sink, "get_robust_list\n"); } break;
					// case SYS_splice: { fprintf(sink, "splice\n"); } break;
					// case SYS_tee: { fprintf(sink, "tee\n"); } break;
					// case SYS_sync_file_range: { fprintf(sink, "sync_file_range\n"); } break;
					// case SYS_vmsplice: { fprintf(sink, "vmsplice\n"); } break;
					// case SYS_move_pages: { fprintf(sink, "move_pages\n"); } break;
					// case SYS_utimensat: { fprintf(sink, "utimensat\n"); } break;
					// case SYS_epoll_pwait: { fprintf(sink, "epoll_pwait\n"); } break;
					// case SYS_signalfd: { fprintf(sink, "signalfd\n"); } break;
					// case SYS_timerfd_create: { fprintf(sink, "timerfd_create\n"); } break;
					// case SYS_eventfd: { fprintf(sink, "eventfd\n"); } break;
					// case SYS_fallocate: { fprintf(sink, "fallocate\n"); } break;
					// case SYS_timerfd_settime: { fprintf(sink, "timerfd_settime\n"); } break;
					// case SYS_timerfd_gettime: { fprintf(sink, "timerfd_gettime\n"); } break;
					// case SYS_accept4: { fprintf(sink, "accept4\n"); } break;
					// case SYS_signalfd4: { fprintf(sink, "signalfd4\n"); } break;
					// case SYS_eventfd2: { fprintf(sink, "eventfd2\n"); } break;
					// case SYS_epoll_create1: { fprintf(sink, "epoll_create1\n"); } break;
					// case SYS_dup3: { fprintf(sink, "dup3\n"); } break;
					// case SYS_pipe2: { fprintf(sink, "pipe2\n"); } break;
					// case SYS_inotify_init1: { fprintf(sink, "inotify_init1\n"); } break;
					// case SYS_preadv: { fprintf(sink, "preadv\n"); } break;
					// case SYS_pwritev: { fprintf(sink, "pwritev\n"); } break;
					// case SYS_rt_tgsigqueueinfo: { fprintf(sink, "rt_tgsigqueueinfo\n"); } break;
					// case SYS_perf_event_open: { fprintf(sink, "perf_event_open\n"); } break;
					// case SYS_recvmmsg: { fprintf(sink, "recvmmsg\n"); } break;
					// case SYS_fanotify_init: { fprintf(sink, "fanotify_init\n"); } break;
					// case SYS_fanotify_mark: { fprintf(sink, "fanotify_mark\n"); } break;
					// case SYS_prlimit64: { fprintf(sink, "prlimit64\n"); } break;
					// case SYS_name_to_handle_at: { fprintf(sink, "name_to_handle_at\n"); } break;
					// case SYS_open_by_handle_at: { fprintf(sink, "open_by_handle_at\n"); } break;
					// case SYS_clock_adjtime: { fprintf(sink, "clock_adjtime\n"); } break;
					// case SYS_syncfs: { fprintf(sink, "syncfs\n"); } break;
					// case SYS_sendmmsg: { fprintf(sink, "sendmmsg\n"); } break;
					// case SYS_setns: { fprintf(sink, "setns\n"); } break;
					// case SYS_getcpu: { fprintf(sink, "getcpu\n"); } break;
					// case SYS_process_vm_readv: { fprintf(sink, "process_vm_readv\n"); } break;
					// case SYS_process_vm_writev: { fprintf(sink, "process_vm_writev\n"); } break;
					// case SYS_kcmp: { fprintf(sink, "kcmp\n"); } break;
					// case SYS_finit_module: { fprintf(sink, "finit_module\n"); } break;
					// case SYS_sched_setattr: { fprintf(sink, "sched_setattr\n"); } break;
					// case SYS_sched_getattr: { fprintf(sink, "sched_getattr\n"); } break;
					// case SYS_renameat2: { fprintf(sink, "renameat2\n"); } break;
					// case SYS_seccomp: { fprintf(sink, "seccomp\n"); } break;
					// case SYS_getrandom: { fprintf(sink, "getrandom\n"); } break;
					// case SYS_memfd_create: { fprintf(sink, "memfd_create\n"); } break;
					// case SYS_kexec_file_load: { fprintf(sink, "kexec_file_load\n"); } break;
					// case SYS_bpf: { fprintf(sink, "bpf\n"); } break;
					// case SYS_execveat: { fprintf(sink, "execveat\n"); } break;
					// case SYS_userfaultfd: { fprintf(sink, "userfaultfd\n"); } break;
					// case SYS_membarrier: { fprintf(sink, "membarrier\n"); } break;
					// case SYS_mlock2: { fprintf(sink, "mlock2\n"); } break;
					// case SYS_copy_file_range: { fprintf(sink, "copy_file_range\n"); } break;
					// case SYS_preadv2: { fprintf(sink, "preadv2\n"); } break;
					// case SYS_pwritev2: { fprintf(sink, "pwritev2\n"); } break;
					// case SYS_pkey_mprotect: { fprintf(sink, "pkey_mprotect\n"); } break;
					// case SYS_pkey_alloc: { fprintf(sink, "pkey_alloc\n"); } break;
					// case SYS_pkey_free: { fprintf(sink, "pkey_free\n"); } break;
					// case SYS_statx: { fprintf(sink, "statx\n"); } break;
					// case SYS_io_pgetevents: { fprintf(sink, "io_pgetevents\n"); } break;
					// case SYS_rseq: { fprintf(sink, "rseq\n"); } break;
					// case SYS_pidfd_send_signal: { fprintf(sink, "pidfd_send_signal\n"); } break;
					// case SYS_io_uring_setup: { fprintf(sink, "io_uring_setup\n"); } break;
					// case SYS_io_uring_enter: { fprintf(sink, "io_uring_enter\n"); } break;
					// case SYS_io_uring_register: { fprintf(sink, "io_uring_register\n"); } break;
					// case SYS_open_tree: { fprintf(sink, "open_tree\n"); } break;
					// case SYS_move_mount: { fprintf(sink, "move_mount\n"); } break;
					// case SYS_fsopen: { fprintf(sink, "fsopen\n"); } break;
					// case SYS_fsconfig: { fprintf(sink, "fsconfig\n"); } break;
					// case SYS_fsmount: { fprintf(sink, "fsmount\n"); } break;
					// case SYS_fspick: { fprintf(sink, "fspick\n"); } break;
					// case SYS_pidfd_open: { fprintf(sink, "pidfd_open\n"); } break;
					// case SYS_clone3: { fprintf(sink, "clone3\n"); } break;
					// case SYS_close_range: { fprintf(sink, "close_range\n"); } break;
					// case SYS_openat2: { fprintf(sink, "openat2\n"); } break;
					// case SYS_pidfd_getfd: { fprintf(sink, "pidfd_getfd\n"); } break;
					// case SYS_faccessat2: { fprintf(sink, "faccessat2\n"); } break;
					// case SYS_process_madvise: { fprintf(sink, "process_madvise\n"); } break;
					// case SYS_epoll_pwait2: { fprintf(sink, "epoll_pwait2\n"); } break;
					// case SYS_mount_setattr: { fprintf(sink, "mount_setattr\n"); } break;
					// case SYS_quotactl_fd: { fprintf(sink, "quotactl_fd\n"); } break;
					// case SYS_landlock_create_ruleset: { fprintf(sink, "landlock_create_ruleset\n"); } break;
					// case SYS_landlock_add_rule: { fprintf(sink, "landlock_add_rule\n"); } break;
					// case SYS_landlock_restrict_self: { fprintf(sink, "landlock_restrict_self\n"); } break;
					// case SYS_memfd_secret: { fprintf(sink, "memfd_secret\n"); } break;
					// case SYS_process_mrelease: { fprintf(sink, "process_mrelease\n"); } break;

					// default: { // TODO: uncomment when implemented all the syscalls
					// 	assert(0 && "unreachable");
					// }
			}

			ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
		}
	}

	return 0;
}
