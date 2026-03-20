// Sandbox hardening: seccomp BPF filters and Linux capability management.
//
// Provides per-component syscall filters that restrict each SIGINT process
// to the minimum set of syscalls it needs. Also provides helpers for
// dropping capabilities after initialization.
//
// Seccomp filters use classic BPF (not eBPF). Each filter is a static
// array of BPF instructions that validates the syscall number against
// an allow-list and kills the process on any disallowed call.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const SECCOMP = linux.SECCOMP;

// ---- BPF instruction definitions ----

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

// BPF opcodes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

fn bpf_stmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// seccomp_data field offsets
const SECCOMP_DATA_NR_OFFSET: u32 = @offsetOf(SECCOMP.data, "nr");
const SECCOMP_DATA_ARCH_OFFSET: u32 = @offsetOf(SECCOMP.data, "arch");

// AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
// = 62 | 0x80000000 | 0x40000000 = 0xC000003E
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

const PR_SET_NO_NEW_PRIVS: i32 = 38;

/// Set PR_SET_NO_NEW_PRIVS (required before seccomp filter install).
pub fn setNoNewPrivs() !void {
    const rc = linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (rc != 0) return error.PrctlFailed;
}

/// Install a seccomp BPF filter from a static instruction array.
fn installFilter(filter: []const SockFilter) !void {
    const prog = SockFprog{
        .len = @intCast(filter.len),
        .filter = filter.ptr,
    };
    const rc = linux.seccomp(SECCOMP.SET_MODE_FILTER, 0, @ptrCast(&prog));
    if (rc != 0) return error.SeccompInstallFailed;
}

/// Build a comptime seccomp allow-list filter.
/// Layout: [load arch][check arch][kill on mismatch][load nr][N x check syscall][kill default][allow]
fn buildAllowFilter(comptime allowed: []const linux.SYS) []const SockFilter {
    const n = allowed.len;
    const total = 4 + n + 2; // 4 preamble + n checks + kill + allow

    comptime var filter: [total]SockFilter = undefined;
    comptime var idx: usize = 0;

    // [0] Load architecture
    filter[idx] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET);
    idx += 1;

    // [1] Check arch == x86_64; match → skip kill (jt=1), mismatch → fall through to kill (jf=0)
    filter[idx] = bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    idx += 1;

    // [2] Kill on arch mismatch
    filter[idx] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.KILL_PROCESS);
    idx += 1;

    // [3] Load syscall number
    filter[idx] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET);
    idx += 1;

    // [4..4+n-1] Check each allowed syscall
    for (allowed) |sys| {
        // On match, jump to ALLOW at index (total - 1). Distance from here = total - 1 - idx - 1.
        const dist: u8 = @intCast(total - 1 - idx - 1);
        filter[idx] = bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, @intFromEnum(sys), dist, 0);
        idx += 1;
    }

    // [4+n] Default: kill
    filter[idx] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.KILL_PROCESS);
    idx += 1;

    // [4+n+1] Allow
    filter[idx] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.ALLOW);
    idx += 1;

    return &filter;
}

// ---- Per-component syscall allow-lists ----

const collector_allowed = [_]linux.SYS{
    .read,        .write,       .close,          .poll,
    .ioctl,       .mmap,        .munmap,         .mprotect,
    .brk,         .socket,      .connect,        .sendto,
    .recvfrom,    .bind,        .listen,         .accept,
    .getsockopt,  .setsockopt,  .rt_sigaction,   .rt_sigprocmask,
    .rt_sigreturn,.openat,      .fstat,          .exit_group,
    .clock_gettime,.getrandom,  .futex,
};

const analyzer_allowed = [_]linux.SYS{
    .read,        .write,       .close,          .poll,
    .mmap,        .munmap,      .mprotect,       .brk,
    .socket,      .connect,     .sendto,         .recvfrom,
    .bind,        .listen,      .accept,         .getsockopt,
    .setsockopt,  .rt_sigaction,.rt_sigprocmask, .rt_sigreturn,
    .openat,      .fstat,       .exit_group,     .clock_gettime,
    .getrandom,   .futex,
};

const enforcer_allowed = [_]linux.SYS{
    .read,        .write,       .close,          .poll,
    .mmap,        .munmap,      .mprotect,       .brk,
    .socket,      .connect,     .sendto,         .recvfrom,
    .bind,        .listen,      .accept,         .getsockopt,
    .setsockopt,  .rt_sigaction,.rt_sigprocmask, .rt_sigreturn,
    .openat,      .fstat,       .exit_group,     .clock_gettime,
    .getrandom,   .futex,       .clone,          .execve,
    .wait4,       .pipe2,       .dup2,
};

/// Install the collector's seccomp filter.
pub fn installCollectorFilter() !void {
    try setNoNewPrivs();
    try installFilter(comptime buildAllowFilter(&collector_allowed));
}

/// Install the analyzer's seccomp filter.
pub fn installAnalyzerFilter() !void {
    try setNoNewPrivs();
    try installFilter(comptime buildAllowFilter(&analyzer_allowed));
}

/// Install the enforcer's seccomp filter.
pub fn installEnforcerFilter() !void {
    try setNoNewPrivs();
    try installFilter(comptime buildAllowFilter(&enforcer_allowed));
}

// ---- Capability management ----

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

/// CAP constants from linux/capability.h.
pub const CAP = struct {
    pub const DAC_READ_SEARCH: u8 = 2;
    pub const SYS_RAWIO: u8 = 17;
    pub const SYS_ADMIN: u8 = 21;
    pub const SYS_BOOT: u8 = 22;
};

/// Drop all capabilities except those in `keep`.
pub fn dropCapabilities(keep: []const u8) !void {
    var header = linux.cap_user_header_t{
        .version = LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    var effective: u32 = 0;
    var permitted: u32 = 0;
    for (keep) |cap| {
        const mask = @as(u32, 1) << @as(u5, @intCast(cap));
        effective |= mask;
        permitted |= mask;
    }
    var data = linux.cap_user_data_t{
        .effective = effective,
        .permitted = permitted,
        .inheritable = 0,
    };
    const rc = linux.capset(&header, &data);
    if (rc != 0) return error.CapsetFailed;
}

/// Drop ALL capabilities.
pub fn dropAllCapabilities() !void {
    try dropCapabilities(&.{});
}

// ---- Tests ----

test "buildAllowFilter produces valid BPF program" {
    const test_allowed = [_]linux.SYS{ .read, .write, .close };
    const filter = comptime buildAllowFilter(&test_allowed);

    // 4 preamble + 3 checks + kill + allow = 9
    try std.testing.expectEqual(@as(usize, 9), filter.len);

    // First instruction loads arch
    try std.testing.expectEqual(BPF_LD | BPF_W | BPF_ABS, filter[0].code);
    try std.testing.expectEqual(SECCOMP_DATA_ARCH_OFFSET, filter[0].k);

    // Last instruction is ALLOW
    try std.testing.expectEqual(BPF_RET | BPF_K, filter[filter.len - 1].code);
    try std.testing.expectEqual(SECCOMP.RET.ALLOW, filter[filter.len - 1].k);

    // Second to last is KILL
    try std.testing.expectEqual(BPF_RET | BPF_K, filter[filter.len - 2].code);
    try std.testing.expectEqual(SECCOMP.RET.KILL_PROCESS, filter[filter.len - 2].k);
}

test "collector filter has expected size" {
    const filter = comptime buildAllowFilter(&collector_allowed);
    try std.testing.expectEqual(@as(usize, 4 + collector_allowed.len + 2), filter.len);
}

test "setNoNewPrivs succeeds" {
    try setNoNewPrivs();
}
