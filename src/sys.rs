//! Process limits (Linux; no-ops elsewhere).
//!
//! Docker 25+ / containerd 2 start containers with a soft open-file limit
//! of 1024 (hard limit much higher). Every player holds one or two
//! sockets, so 1024 caps the server near 500 players long before the CPU
//! does: the server raises its soft limit to the hard one at startup.

/// (soft, hard) open-file limit.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn fd_limit() -> Option<(u64, u64)> {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct it is given
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } == 0)
        .then_some((r.rlim_cur, r.rlim_max))
}

#[cfg(not(target_os = "linux"))]
pub fn fd_limit() -> Option<(u64, u64)> {
    None
}

/// Raise the soft open-file limit to the hard limit; the new (soft, hard).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn raise_fd_limit() -> Option<(u64, u64)> {
    let (soft, hard) = fd_limit()?;
    if soft < hard {
        let r = libc::rlimit {
            rlim_cur: hard,
            rlim_max: hard,
        };
        // SAFETY: setrlimit only reads the struct it is given
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) } != 0 {
            log::warn!(
                "open files: soft limit {soft} could not be raised to {hard}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    fd_limit()
}

#[cfg(not(target_os = "linux"))]
pub fn raise_fd_limit() -> Option<(u64, u64)> {
    None
}

/// The memory limit of this process's cgroup, MB (v2 `memory.max`, v1
/// `memory.limit_in_bytes`); `None` = unlimited or unknown.
pub fn memory_limit_mb() -> Option<f64> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in cg.lines() {
        let mut it = line.splitn(3, ':');
        let (_, ctrl, path) = (it.next()?, it.next()?, it.next()?);
        let file = if ctrl.is_empty() {
            format!("/sys/fs/cgroup{path}/memory.max")
        } else if ctrl.split(',').any(|c| c == "memory") {
            format!("/sys/fs/cgroup/memory{path}/memory.limit_in_bytes")
        } else {
            continue;
        };
        // inside a container the cgroup root is the container's own
        for f in [
            file.clone(),
            "/sys/fs/cgroup/memory.max".into(),
            "/sys/fs/cgroup/memory/memory.limit_in_bytes".into(),
        ] {
            if let Ok(v) = std::fs::read_to_string(&f)
                && let Ok(b) = v.trim().parse::<f64>()
                && b < 1e15
            {
                return Some(b / (1024.0 * 1024.0));
            }
        }
    }
    None
}

/// Open file descriptors of this process (`/proc/self/fd`).
pub fn open_fds() -> Option<u64> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|d| d.count() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_soft_fd_limit_goes_up_to_the_hard_one() {
        let (_, hard) = fd_limit().unwrap();
        let (soft, hard2) = raise_fd_limit().unwrap();
        assert_eq!((soft, hard2), (hard, hard));
        assert!(open_fds().unwrap() > 0);
    }
}
