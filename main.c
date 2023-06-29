#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void print_opened_filename(pid_t child_pid, unsigned long addr) {
	const static size_t long_size = sizeof(long);

	char filename[NAME_MAX];
	unsigned long data;
	int i = 0;

	while (1) {
		data = ptrace(PTRACE_PEEKDATA, child_pid, addr + i * long_size, NULL);
		memcpy(filename + i * long_size, &data, long_size);

		if (memchr(&data, 0, long_size) != NULL)
			break;

		i++;
	}

	printf("Opened Filename: %s\n", filename);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
		return 1;
	}

	FILE *sink = stderr;

	pid_t child_pid = fork();
	if (child_pid == -1) {
		perror("failed to fork a child");
		return 1;
	}

	if (child_pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("failed to trace the child");
			return 1;
		}
		execvp(argv[1], argv + 1);
		perror("failed to execute the child");
		return 1;
	} else {
		int status;

		while (waitpid(child_pid, &status, 0) && !WIFEXITED(status)) {
			struct user_regs_struct regs;

			ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

			fprintf(sink, "%llu: ", regs.orig_rax);

			switch (regs.orig_rax) {
				case 0: {
					fprintf(sink, "read\n");
				} break;
				case 1: {
					fprintf(sink, "write\n");
				} break;
				case 2: {
					fprintf(sink, "open\n");
				} break;
				case 3: {
					fprintf(sink, "close\n");
				} break;
				case 4: {
					fprintf(sink, "stat\n");
				} break;
				case 5: {
					fprintf(sink, "fstat\n");
				} break;
				case 6: {
					fprintf(sink, "lstat\n");
				} break;
				case 7: {
					fprintf(sink, "poll\n");
				} break;
				case 8: {
					fprintf(sink, "lseek\n");
				} break;
				case 9: {
					fprintf(sink, "mmap\n");
				} break;
				case 10: {
					fprintf(sink, "mprotect\n");
				} break;
				case 11: {
					fprintf(sink, "munmap\n");
				} break;
				case 12: {
					fprintf(sink, "brk\n");
				} break;
				case 13: {
					fprintf(sink, "rt_sigaction\n");
				} break;
				case 14: {
					fprintf(sink, "rt_sigprocmask\n");
				} break;
				case 15: {
					fprintf(sink, "rt_sigreturn\n");
				} break;
				case 16: {
					fprintf(sink, "ioctl\n");
				} break;
				case 17: {
					fprintf(sink, "pread64\n");
				} break;
				case 18: {
					fprintf(sink, "pwrite64\n");
				} break;
				case 19: {
					fprintf(sink, "readv\n");
				} break;
				case 20: {
					fprintf(sink, "writev\n");
				} break;
				case 21: {
					fprintf(sink, "access\n");
				} break;
				case 22: {
					fprintf(sink, "pipe\n");
				} break;
				case 23: {
					fprintf(sink, "select\n");
				} break;
				case 24: {
					fprintf(sink, "sched_yield\n");
				} break;
				case 25: {
					fprintf(sink, "mremap\n");
				} break;
				case 26: {
					fprintf(sink, "msync\n");
				} break;
				case 27: {
					fprintf(sink, "mincore\n");
				} break;
				case 28: {
					fprintf(sink, "madvise\n");
				} break;
				case 29: {
					fprintf(sink, "shmget\n");
				} break;
				case 30: {
					fprintf(sink, "shmat\n");
				} break;
				case 31: {
					fprintf(sink, "shmctl\n");
				} break;
				case 32: {
					fprintf(sink, "dup\n");
				} break;
				case 33: {
					fprintf(sink, "dup2\n");
				} break;
				case 34: {
					fprintf(sink, "pause\n");
				} break;
				case 35: {
					fprintf(sink, "nanosleep\n");
				} break;
				case 36: {
					fprintf(sink, "getitimer\n");
				} break;
				case 37: {
					fprintf(sink, "alarm\n");
				} break;
				case 38: {
					fprintf(sink, "setitimer\n");
				} break;
				case 39: {
					fprintf(sink, "getpid\n");
				} break;
				case 40: {
					fprintf(sink, "sendfile\n");
				} break;
				case 41: {
					fprintf(sink, "socket\n");
				} break;
				case 42: {
					fprintf(sink, "connect\n");
				} break;
				case 43: {
					fprintf(sink, "accept\n");
				} break;
				case 44: {
					fprintf(sink, "sendto\n");
				} break;
				case 45: {
					fprintf(sink, "recvfrom\n");
				} break;
				case 46: {
					fprintf(sink, "sendmsg\n");
				} break;
				case 47: {
					fprintf(sink, "recvmsg\n");
				} break;
				case 48: {
					fprintf(sink, "shutdown\n");
				} break;
				case 49: {
					fprintf(sink, "bind\n");
				} break;
				case 50: {
					fprintf(sink, "listen\n");
				} break;
				case 51: {
					fprintf(sink, "getsockname\n");
				} break;
				case 52: {
					fprintf(sink, "getpeername\n");
				} break;
				case 53: {
					fprintf(sink, "socketpair\n");
				} break;
				case 54: {
					fprintf(sink, "setsockopt\n");
				} break;
				case 55: {
					fprintf(sink, "getsockopt\n");
				} break;
				case 56: {
					fprintf(sink, "clone\n");
				} break;
				case 57: {
					fprintf(sink, "fork\n");
				} break;
				case 58: {
					fprintf(sink, "vfork\n");
				} break;
				case 59: {
					fprintf(sink, "execve\n");
				} break;
				case 60: {
					fprintf(sink, "exit\n");
				} break;
				case 61: {
					fprintf(sink, "wait4\n");
				} break;
				case 62: {
					fprintf(sink, "kill\n");
				} break;
				case 63: {
					fprintf(sink, "uname\n");
				} break;
				case 64: {
					fprintf(sink, "semget\n");
				} break;
				case 65: {
					fprintf(sink, "semop\n");
				} break;
				case 66: {
					fprintf(sink, "semctl\n");
				} break;
				case 67: {
					fprintf(sink, "shmdt\n");
				} break;
				case 68: {
					fprintf(sink, "msgget\n");
				} break;
				case 69: {
					fprintf(sink, "msgsnd\n");
				} break;
				case 70: {
					fprintf(sink, "msgrcv\n");
				} break;
				case 71: {
					fprintf(sink, "msgctl\n");
				} break;
				case 72: {
					fprintf(sink, "fcntl\n");
				} break;
				case 73: {
					fprintf(sink, "flock\n");
				} break;
				case 74: {
					fprintf(sink, "fsync\n");
				} break;
				case 75: {
					fprintf(sink, "fdatasync\n");
				} break;
				case 76: {
					fprintf(sink, "truncate\n");
				} break;
				case 77: {
					fprintf(sink, "ftruncate\n");
				} break;
				case 78: {
					fprintf(sink, "getdents\n");
				} break;
				case 79: {
					fprintf(sink, "getcwd\n");
				} break;
				case 80: {
					fprintf(sink, "chdir\n");
				} break;
				case 81: {
					fprintf(sink, "fchdir\n");
				} break;
				case 82: {
					fprintf(sink, "rename\n");
				} break;
				case 83: {
					fprintf(sink, "mkdir\n");
				} break;
				case 84: {
					fprintf(sink, "rmdir\n");
				} break;
				case 85: {
					fprintf(sink, "creat\n");
				} break;
				case 86: {
					fprintf(sink, "link\n");
				} break;
				case 87: {
					fprintf(sink, "unlink\n");
				} break;
				case 88: {
					fprintf(sink, "symlink\n");
				} break;
				case 89: {
					fprintf(sink, "readlink\n");
				} break;
				case 90: {
					fprintf(sink, "chmod\n");
				} break;
				case 91: {
					fprintf(sink, "fchmod\n");
				} break;
				case 92: {
					fprintf(sink, "chown\n");
				} break;
				case 93: {
					fprintf(sink, "fchown\n");
				} break;
				case 94: {
					fprintf(sink, "lchown\n");
				} break;
				case 95: {
					fprintf(sink, "umask\n");
				} break;
				case 96: {
					fprintf(sink, "gettimeofday\n");
				} break;
				case 97: {
					fprintf(sink, "getrlimit\n");
				} break;
				case 98: {
					fprintf(sink, "getrusage\n");
				} break;
				case 99: {
					fprintf(sink, "sysinfo\n");
				} break;
				case 100: {
					fprintf(sink, "times\n");
				} break;
				case 101: {
					fprintf(sink, "ptrace\n");
				} break;
				case 102: {
					fprintf(sink, "getuid\n");
				} break;
				case 103: {
					fprintf(sink, "syslog\n");
				} break;
				case 104: {
					fprintf(sink, "getgid\n");
				} break;
				case 105: {
					fprintf(sink, "setuid\n");
				} break;
				case 106: {
					fprintf(sink, "setgid\n");
				} break;
				case 107: {
					fprintf(sink, "geteuid\n");
				} break;
				case 108: {
					fprintf(sink, "getegid\n");
				} break;
				case 109: {
					fprintf(sink, "setpgid\n");
				} break;
				case 110: {
					fprintf(sink, "getppid\n");
				} break;
				case 111: {
					fprintf(sink, "getpgrp\n");
				} break;
				case 112: {
					fprintf(sink, "setsid\n");
				} break;
				case 113: {
					fprintf(sink, "setreuid\n");
				} break;
				case 114: {
					fprintf(sink, "setregid\n");
				} break;
				case 115: {
					fprintf(sink, "getgroups\n");
				} break;
				case 116: {
					fprintf(sink, "setgroups\n");
				} break;
				case 117: {
					fprintf(sink, "setresuid\n");
				} break;
				case 118: {
					fprintf(sink, "getresuid\n");
				} break;
				case 119: {
					fprintf(sink, "setresgid\n");
				} break;
				case 120: {
					fprintf(sink, "getresgid\n");
				} break;
				case 121: {
					fprintf(sink, "getpgid\n");
				} break;
				case 122: {
					fprintf(sink, "setfsuid\n");
				} break;
				case 123: {
					fprintf(sink, "setfsgid\n");
				} break;
				case 124: {
					fprintf(sink, "getsid\n");
				} break;
				case 125: {
					fprintf(sink, "capget\n");
				} break;
				case 126: {
					fprintf(sink, "capset\n");
				} break;
				case 127: {
					fprintf(sink, "rt_sigpending\n");
				} break;
				case 128: {
					fprintf(sink, "rt_sigtimedwait\n");
				} break;
				case 129: {
					fprintf(sink, "rt_sigqueueinfo\n");
				} break;
				case 130: {
					fprintf(sink, "rt_sigsuspend\n");
				} break;
				case 131: {
					fprintf(sink, "sigaltstack\n");
				} break;
				case 132: {
					fprintf(sink, "utime\n");
				} break;
				case 133: {
					fprintf(sink, "mknod\n");
				} break;
				case 134: {
					fprintf(sink, "uselib\n");
				} break;
				case 135: {
					fprintf(sink, "personality\n");
				} break;
				case 136: {
					fprintf(sink, "ustat\n");
				} break;
				case 137: {
					fprintf(sink, "statfs\n");
				} break;
				case 138: {
					fprintf(sink, "fstatfs\n");
				} break;
				case 139: {
					fprintf(sink, "sysfs\n");
				} break;
				case 140: {
					fprintf(sink, "getpriority\n");
				} break;
				case 141: {
					fprintf(sink, "setpriority\n");
				} break;
				case 142: {
					fprintf(sink, "sched_setparam\n");
				} break;
				case 143: {
					fprintf(sink, "sched_getparam\n");
				} break;
				case 144: {
					fprintf(sink, "sched_setscheduler\n");
				} break;
				case 145: {
					fprintf(sink, "sched_getscheduler\n");
				} break;
				case 146: {
					fprintf(sink, "sched_get_priority_max\n");
				} break;
				case 147: {
					fprintf(sink, "sched_get_priority_min\n");
				} break;
				case 148: {
					fprintf(sink, "sched_rr_get_interval\n");
				} break;
				case 149: {
					fprintf(sink, "mlock\n");
				} break;
				case 150: {
					fprintf(sink, "munlock\n");
				} break;
				case 151: {
					fprintf(sink, "mlockall\n");
				} break;
				case 152: {
					fprintf(sink, "munlockall\n");
				} break;
				case 153: {
					fprintf(sink, "vhangup\n");
				} break;
				case 154: {
					fprintf(sink, "modify_ldt\n");
				} break;
				case 155: {
					fprintf(sink, "pivot_root\n");
				} break;
				case 156: {
					fprintf(sink, "_sysctl\n");
				} break;
				case 157: {
					fprintf(sink, "prctl\n");
				} break;
				case 158: {
					fprintf(sink, "arch_prctl\n");
				} break;
				case 159: {
					fprintf(sink, "adjtimex\n");
				} break;
				case 160: {
					fprintf(sink, "setrlimit\n");
				} break;
				case 161: {
					fprintf(sink, "chroot\n");
				} break;
				case 162: {
					fprintf(sink, "sync\n");
				} break;
				case 163: {
					fprintf(sink, "acct\n");
				} break;
				case 164: {
					fprintf(sink, "settimeofday\n");
				} break;
				case 165: {
					fprintf(sink, "mount\n");
				} break;
				case 166: {
					fprintf(sink, "umount2\n");
				} break;
				case 167: {
					fprintf(sink, "swapon\n");
				} break;
				case 168: {
					fprintf(sink, "swapoff\n");
				} break;
				case 169: {
					fprintf(sink, "reboot\n");
				} break;
				case 170: {
					fprintf(sink, "sethostname\n");
				} break;
				case 171: {
					fprintf(sink, "setdomainname\n");
				} break;
				case 172: {
					fprintf(sink, "iopl\n");
				} break;
				case 173: {
					fprintf(sink, "ioperm\n");
				} break;
				case 174: {
					fprintf(sink, "create_module\n");
				} break;
				case 175: {
					fprintf(sink, "init_module\n");
				} break;
				case 176: {
					fprintf(sink, "delete_module\n");
				} break;
				case 177: {
					fprintf(sink, "get_kernel_syms\n");
				} break;
				case 178: {
					fprintf(sink, "query_module\n");
				} break;
				case 179: {
					fprintf(sink, "quotactl\n");
				} break;
				case 180: {
					fprintf(sink, "nfsservctl\n");
				} break;
				case 181: {
					fprintf(sink, "getpmsg\n");
				} break;
				case 182: {
					fprintf(sink, "putpmsg\n");
				} break;
				case 183: {
					fprintf(sink, "afs_syscall\n");
				} break;
				case 184: {
					fprintf(sink, "tuxcall\n");
				} break;
				case 185: {
					fprintf(sink, "security\n");
				} break;
				case 186: {
					fprintf(sink, "gettid\n");
				} break;
				case 187: {
					fprintf(sink, "readahead\n");
				} break;
				case 188: {
					fprintf(sink, "setxattr\n");
				} break;
				case 189: {
					fprintf(sink, "lsetxattr\n");
				} break;
				case 190: {
					fprintf(sink, "fsetxattr\n");
				} break;
				case 191: {
					fprintf(sink, "getxattr\n");
				} break;
				case 192: {
					fprintf(sink, "lgetxattr\n");
				} break;
				case 193: {
					fprintf(sink, "fgetxattr\n");
				} break;
				case 194: {
					fprintf(sink, "listxattr\n");
				} break;
				case 195: {
					fprintf(sink, "llistxattr\n");
				} break;
				case 196: {
					fprintf(sink, "flistxattr\n");
				} break;
				case 197: {
					fprintf(sink, "removexattr\n");
				} break;
				case 198: {
					fprintf(sink, "lremovexattr\n");
				} break;
				case 199: {
					fprintf(sink, "fremovexattr\n");
				} break;
				case 200: {
					fprintf(sink, "tkill\n");
				} break;
				case 201: {
					fprintf(sink, "time\n");
				} break;
				case 202: {
					fprintf(sink, "futex\n");
				} break;
				case 203: {
					fprintf(sink, "sched_setaffinity\n");
				} break;
				case 204: {
					fprintf(sink, "sched_getaffinity\n");
				} break;
				case 205: {
					fprintf(sink, "set_thread_area\n");
				} break;
				case 206: {
					fprintf(sink, "io_setup\n");
				} break;
				case 207: {
					fprintf(sink, "io_destroy\n");
				} break;
				case 208: {
					fprintf(sink, "io_getevents\n");
				} break;
				case 209: {
					fprintf(sink, "io_submit\n");
				} break;
				case 210: {
					fprintf(sink, "io_cancel\n");
				} break;
				case 211: {
					fprintf(sink, "get_thread_area\n");
				} break;
				case 212: {
					fprintf(sink, "lookup_dcookie\n");
				} break;
				case 213: {
					fprintf(sink, "epoll_create\n");
				} break;
				case 214: {
					fprintf(sink, "epoll_ctl_old\n");
				} break;
				case 215: {
					fprintf(sink, "epoll_wait_old\n");
				} break;
				case 216: {
					fprintf(sink, "remap_file_pages\n");
				} break;
				case 217: {
					fprintf(sink, "getdents64\n");
				} break;
				case 218: {
					fprintf(sink, "set_tid_address\n");
				} break;
				case 219: {
					fprintf(sink, "restart_syscall\n");
				} break;
				case 220: {
					fprintf(sink, "semtimedop\n");
				} break;
				case 221: {
					fprintf(sink, "fadvise64\n");
				} break;
				case 222: {
					fprintf(sink, "timer_create\n");
				} break;
				case 223: {
					fprintf(sink, "timer_settime\n");
				} break;
				case 224: {
					fprintf(sink, "timer_gettime\n");
				} break;
				case 225: {
					fprintf(sink, "timer_getoverrun\n");
				} break;
				case 226: {
					fprintf(sink, "timer_delete\n");
				} break;
				case 227: {
					fprintf(sink, "clock_settime\n");
				} break;
				case 228: {
					fprintf(sink, "clock_gettime\n");
				} break;
				case 229: {
					fprintf(sink, "clock_getres\n");
				} break;
				case 230: {
					fprintf(sink, "clock_nanosleep\n");
				} break;
				case 231: {
					fprintf(sink, "exit_group\n");
				} break;
				case 232: {
					fprintf(sink, "epoll_wait\n");
				} break;
				case 233: {
					fprintf(sink, "epoll_ctl\n");
				} break;
				case 234: {
					fprintf(sink, "tgkill\n");
				} break;
				case 235: {
					fprintf(sink, "utimes\n");
				} break;
				case 236: {
					fprintf(sink, "vserver\n");
				} break;
				case 237: {
					fprintf(sink, "mbind\n");
				} break;
				case 238: {
					fprintf(sink, "set_mempolicy\n");
				} break;
				case 239: {
					fprintf(sink, "get_mempolicy\n");
				} break;
				case 240: {
					fprintf(sink, "mq_open\n");
				} break;
				case 241: {
					fprintf(sink, "mq_unlink\n");
				} break;
				case 242: {
					fprintf(sink, "mq_timedsend\n");
				} break;
				case 243: {
					fprintf(sink, "mq_timedreceive\n");
				} break;
				case 244: {
					fprintf(sink, "mq_notify\n");
				} break;
				case 245: {
					fprintf(sink, "mq_getsetattr\n");
				} break;
				case 246: {
					fprintf(sink, "kexec_load\n");
				} break;
				case 247: {
					fprintf(sink, "waitid\n");
				} break;
				case 248: {
					fprintf(sink, "add_key\n");
				} break;
				case 249: {
					fprintf(sink, "request_key\n");
				} break;
				case 250: {
					fprintf(sink, "keyctl\n");
				} break;
				case 251: {
					fprintf(sink, "ioprio_set\n");
				} break;
				case 252: {
					fprintf(sink, "ioprio_get\n");
				} break;
				case 253: {
					fprintf(sink, "inotify_init\n");
				} break;
				case 254: {
					fprintf(sink, "inotify_add_watch\n");
				} break;
				case 255: {
					fprintf(sink, "inotify_rm_watch\n");
				} break;
				case 256: {
					fprintf(sink, "migrate_pages\n");
				} break;
				case 257: {
					fprintf(sink, "openat\n");
				} break;
				case 258: {
					fprintf(sink, "mkdirat\n");
				} break;
				case 259: {
					fprintf(sink, "mknodat\n");
				} break;
				case 260: {
					fprintf(sink, "fchownat\n");
				} break;
				case 261: {
					fprintf(sink, "futimesat\n");
				} break;
				case 262: {
					fprintf(sink, "newfstatat\n");
				} break;
				case 263: {
					fprintf(sink, "unlinkat\n");
				} break;
				case 264: {
					fprintf(sink, "renameat\n");
				} break;
				case 265: {
					fprintf(sink, "linkat\n");
				} break;
				case 266: {
					fprintf(sink, "symlinkat\n");
				} break;
				case 267: {
					fprintf(sink, "readlinkat\n");
				} break;
				case 268: {
					fprintf(sink, "fchmodat\n");
				} break;
				case 269: {
					fprintf(sink, "faccessat\n");
				} break;
				case 270: {
					fprintf(sink, "pselect6\n");
				} break;
				case 271: {
					fprintf(sink, "ppoll\n");
				} break;
				case 272: {
					fprintf(sink, "unshare\n");
				} break;
				case 273: {
					fprintf(sink, "set_robust_list\n");
				} break;
				case 274: {
					fprintf(sink, "get_robust_list\n");
				} break;
				case 275: {
					fprintf(sink, "splice\n");
				} break;
				case 276: {
					fprintf(sink, "tee\n");
				} break;
				case 277: {
					fprintf(sink, "sync_file_range\n");
				} break;
				case 278: {
					fprintf(sink, "vmsplice\n");
				} break;
				case 279: {
					fprintf(sink, "move_pages\n");
				} break;
				case 280: {
					fprintf(sink, "utimensat\n");
				} break;
				case 281: {
					fprintf(sink, "epoll_pwait\n");
				} break;
				case 282: {
					fprintf(sink, "signalfd\n");
				} break;
				case 283: {
					fprintf(sink, "timerfd_create\n");
				} break;
				case 284: {
					fprintf(sink, "eventfd\n");
				} break;
				case 285: {
					fprintf(sink, "fallocate\n");
				} break;
				case 286: {
					fprintf(sink, "timerfd_settime\n");
				} break;
				case 287: {
					fprintf(sink, "timerfd_gettime\n");
				} break;
				case 288: {
					fprintf(sink, "accept4\n");
				} break;
				case 289: {
					fprintf(sink, "signalfd4\n");
				} break;
				case 290: {
					fprintf(sink, "eventfd2\n");
				} break;
				case 291: {
					fprintf(sink, "epoll_create1\n");
				} break;
				case 292: {
					fprintf(sink, "dup3\n");
				} break;
				case 293: {
					fprintf(sink, "pipe2\n");
				} break;
				case 294: {
					fprintf(sink, "inotify_init1\n");
				} break;
				case 295: {
					fprintf(sink, "preadv\n");
				} break;
				case 296: {
					fprintf(sink, "pwritev\n");
				} break;
				case 297: {
					fprintf(sink, "rt_tgsigqueueinfo\n");
				} break;
				case 298: {
					fprintf(sink, "perf_event_open\n");
				} break;
				case 299: {
					fprintf(sink, "recvmmsg\n");
				} break;
				case 300: {
					fprintf(sink, "fanotify_init\n");
				} break;
				case 301: {
					fprintf(sink, "fanotify_mark\n");
				} break;
				case 302: {
					fprintf(sink, "prlimit64\n");
				} break;
				case 303: {
					fprintf(sink, "name_to_handle_at\n");
				} break;
				case 304: {
					fprintf(sink, "open_by_handle_at\n");
				} break;
				case 305: {
					fprintf(sink, "clock_adjtime\n");
				} break;
				case 306: {
					fprintf(sink, "syncfs\n");
				} break;
				case 307: {
					fprintf(sink, "sendmmsg\n");
				} break;
				case 308: {
					fprintf(sink, "setns\n");
				} break;
				case 309: {
					fprintf(sink, "getcpu\n");
				} break;
				case 310: {
					fprintf(sink, "process_vm_readv\n");
				} break;
				case 311: {
					fprintf(sink, "process_vm_writev\n");
				} break;
				case 312: {
					fprintf(sink, "kcmp\n");
				} break;
				case 313: {
					fprintf(sink, "finit_module\n");
				} break;
				case 314: {
					fprintf(sink, "sched_setattr\n");
				} break;
				case 315: {
					fprintf(sink, "sched_getattr\n");
				} break;
				case 316: {
					fprintf(sink, "renameat2\n");
				} break;
				case 317: {
					fprintf(sink, "seccomp\n");
				} break;
				case 318: {
					fprintf(sink, "getrandom\n");
				} break;
				case 319: {
					fprintf(sink, "memfd_create\n");
				} break;
				case 320: {
					fprintf(sink, "kexec_file_load\n");
				} break;
				case 321: {
					fprintf(sink, "bpf\n");
				} break;
				case 322: {
					fprintf(sink, "execveat\n");
				} break;
				case 323: {
					fprintf(sink, "userfaultfd\n");
				} break;
				case 324: {
					fprintf(sink, "membarrier\n");
				} break;
				case 325: {
					fprintf(sink, "mlock2\n");
				} break;
				case 326: {
					fprintf(sink, "copy_file_range\n");
				} break;
				case 327: {
					fprintf(sink, "preadv2\n");
				} break;
				case 328: {
					fprintf(sink, "pwritev2\n");
				} break;
				case 329: {
					fprintf(sink, "pkey_mprotect\n");
				} break;
				case 330: {
					fprintf(sink, "pkey_alloc\n");
				} break;
				case 331: {
					fprintf(sink, "pkey_free\n");
				} break;
				case 332: {
					fprintf(sink, "statx\n");
				} break;
				case 333: {
					fprintf(sink, "io_pgetevents\n");
				} break;
				case 334: {
					fprintf(sink, "rseq\n");
				} break;
				case 424: {
					fprintf(sink, "pidfd_send_signal\n");
				} break;
				case 425: {
					fprintf(sink, "io_uring_setup\n");
				} break;
				case 426: {
					fprintf(sink, "io_uring_enter\n");
				} break;
				case 427: {
					fprintf(sink, "io_uring_register\n");
				} break;
				case 428: {
					fprintf(sink, "open_tree\n");
				} break;
				case 429: {
					fprintf(sink, "move_mount\n");
				} break;
				case 430: {
					fprintf(sink, "fsopen\n");
				} break;
				case 431: {
					fprintf(sink, "fsconfig\n");
				} break;
				case 432: {
					fprintf(sink, "fsmount\n");
				} break;
				case 433: {
					fprintf(sink, "fspick\n");
				} break;
				case 434: {
					fprintf(sink, "pidfd_open\n");
				} break;
				case 435: {
					fprintf(sink, "clone3\n");
				} break;
				case 436: {
					fprintf(sink, "close_range\n");
				} break;
				case 437: {
					fprintf(sink, "openat2\n");
				} break;
				case 438: {
					fprintf(sink, "pidfd_getfd\n");
				} break;
				case 439: {
					fprintf(sink, "faccessat2\n");
				} break;
				case 440: {
					fprintf(sink, "process_madvise\n");
				} break;
				case 441: {
					fprintf(sink, "epoll_pwait2\n");
				} break;
				case 442: {
					fprintf(sink, "mount_setattr\n");
				} break;
				case 443: {
					fprintf(sink, "quotactl_fd\n");
				} break;
				case 444: {
					fprintf(sink, "landlock_create_ruleset\n");
				} break;
				case 445: {
					fprintf(sink, "landlock_add_rule\n");
				} break;
				case 446: {
					fprintf(sink, "landlock_restrict_self\n");
				} break;
				case 447: {
					fprintf(sink, "memfd_secret\n");
				} break;
				case 448: {
					fprintf(sink, "process_mrelease\n");
				} break;
				default: {
					assert(0 && "unreachable");
				}
			}

			ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
		}
	}

	return 0;
}
