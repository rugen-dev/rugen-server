//! Fixed background threads fed by a bounded queue.
//!
//! Work that used to start a thread per request (re-simulations of
//! disputed matches, TURN API calls) goes to a few long-lived threads
//! instead, so the thread count stays fixed however many matches end at
//! once (production runs under `pids_limit: 256`, and every thread
//! counts). A full queue refuses new work rather than growing: callers
//! decide what a refusal means (see [`Workers::submit`]).

use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

pub struct Workers<T> {
    queue: SyncSender<T>,
    name: &'static str,
}

impl<T: Send + 'static> Workers<T> {
    /// `threads` threads named `name-N`, `queue` jobs waiting at most, each
    /// thread at nice value `nice` (Linux; 0 = unchanged). `work` runs one
    /// job; a panicking job is logged and the thread carries on. The
    /// threads end once the pool is dropped and the queue is drained.
    pub fn spawn(
        name: &'static str,
        threads: usize,
        queue: usize,
        nice: i32,
        work: impl Fn(T) + Send + Sync + 'static,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<T>(queue);
        let rx = Arc::new(Mutex::new(rx));
        let work = Arc::new(work);
        for i in 0..threads.max(1) {
            let (rx, work) = (rx.clone(), work.clone());
            std::thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || {
                    lower_priority(nice);
                    run(name, &rx, &*work);
                })?;
        }
        Ok(Self { queue: tx, name })
    }

    /// Queue a job. False when the queue is full (the job is dropped and
    /// a warning logged) or the threads are gone.
    pub fn submit(&self, job: T) -> bool {
        match self.queue.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                log::warn!("{}: queue full, job dropped", self.name);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

fn run<T>(name: &str, rx: &Mutex<Receiver<T>>, work: &(dyn Fn(T) + Send + Sync)) {
    loop {
        let job = {
            let rx = rx.lock().unwrap_or_else(|p| p.into_inner());
            match rx.recv() {
                Ok(j) => j,
                Err(_) => return,
            }
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(job))).is_err() {
            log::error!("{name}: a job panicked");
        }
    }
}

/// Lower the calling thread's CPU priority (nice value `nice`, Linux:
/// the nice value is per thread). Best effort, no-op elsewhere.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn lower_priority(nice: i32) {
    if nice == 0 {
        return;
    }
    // SAFETY: setpriority only reads its integer arguments; `who` 0 is
    // the calling thread (Linux / NPTL: the nice value is per thread)
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) } != 0 {
        log::debug!("setpriority({nice}): {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lower_priority(_nice: i32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use std::time::{Duration, Instant};

    fn eventually(f: impl Fn() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(10), "timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn jobs_run_on_the_fixed_threads_in_order() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let w = Workers::spawn("t-order", 1, 16, 0, move |n: u32| {
            s.lock()
                .unwrap()
                .push((n, std::thread::current().name().map(str::to_string)));
        })
        .unwrap();
        for n in 0..10 {
            assert!(w.submit(n));
        }
        eventually(|| seen.lock().unwrap().len() == 10);
        let seen = seen.lock().unwrap();
        assert!(seen.iter().map(|(n, _)| *n).eq(0..10));
        assert!(seen.iter().all(|(_, t)| t.as_deref() == Some("t-order-0")));
    }

    #[test]
    fn a_full_queue_refuses_work_instead_of_growing() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate = Mutex::new(gate_rx);
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        let w = Workers::spawn("t-full", 1, 2, 0, move |_: u32| {
            let _ = gate.lock().unwrap().recv();
            r.fetch_add(1, Relaxed);
        })
        .unwrap();
        // one job running (blocked on the gate), then the queue fills up
        assert!(w.submit(0));
        let t = Instant::now();
        let mut accepted = 1;
        while w.submit(accepted) {
            accepted += 1;
            assert!(t.elapsed() < Duration::from_secs(10));
        }
        assert!(accepted <= 3, "1 running + 2 queued, got {accepted}");
        for _ in 0..accepted {
            gate_tx.send(()).unwrap();
        }
        eventually(|| ran.load(Relaxed) == accepted as usize);
        assert!(w.submit(99), "room again once drained");
        gate_tx.send(()).unwrap();
    }

    #[test]
    fn a_panicking_job_does_not_kill_the_thread() {
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        let w = Workers::spawn("t-panic", 1, 4, 0, move |n: u32| {
            assert!(n != 1, "boom");
            r.fetch_add(1, Relaxed);
        })
        .unwrap();
        for n in 0..3 {
            w.submit(n);
        }
        eventually(|| ran.load(Relaxed) == 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workers_can_run_at_a_lower_priority() {
        let nice = Arc::new(Mutex::new(None));
        let n = nice.clone();
        let w = Workers::spawn("t-nice", 1, 1, 10, move |_: ()| {
            // field 19 of /proc/thread-self/stat is the nice value
            let stat = std::fs::read_to_string("/proc/thread-self/stat").unwrap();
            let after = stat.rsplit_once(')').unwrap().1;
            let v: i32 = after.split_whitespace().nth(16).unwrap().parse().unwrap();
            *n.lock().unwrap() = Some(v);
        })
        .unwrap();
        w.submit(());
        eventually(|| nice.lock().unwrap().is_some());
        let v = nice.lock().unwrap().unwrap();
        // already at 10 or more (e.g. under `nice`) stays as it is
        assert!(v >= 10, "nice {v}");
    }
}
