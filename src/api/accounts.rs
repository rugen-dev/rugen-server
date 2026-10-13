//! Named accounts (API 5): username + password on top of the anonymous
//! accounts the lobby always had. See [`rugen_proto::account`] for the
//! routes. Logging in hands out the same kind of 64-hex key `/register`
//! does, so the rest of the API does not change.
//!
//! * Passwords are hashed with Argon2id ([`crate::password`]) outside the
//!   store lock, never logged, never stored or echoed in clear.
//! * Failed logins are limited per username and per client address
//!   ([`LoginGuard`]): a few free tries, then an exponentially growing
//!   lockout. Every refusal says the same thing (`WRONG USERNAME OR
//!   PASSWORD`), and an unknown username costs the same time as a wrong
//!   password.
//! * API 4 (rugen 0.5) clients never see any of this: they keep their
//!   anonymous accounts and free-form names, which can no longer be set to
//!   somebody's username.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rugen_proto::account::{AccountInfo, Session, password_error, username_error};
use serde_json::{Value, json};

use super::{Api, Request, Res, Response, db, err, lock, ok};
use crate::password;
use crate::store::{Account, NameError};

/// The one answer to a failed login, whatever failed.
pub const WRONG: &str = "WRONG USERNAME OR PASSWORD";

/// Failed logins per username before lockouts start.
const USER_FREE: u32 = 5;
/// Failed logins per client address before lockouts start (players behind
/// one NAT share it).
const IP_FREE: u32 = 20;
/// First lockout; each further failure doubles it, up to [`MAX_LOCK`].
const BASE_LOCK: Duration = Duration::from_secs(30);
const MAX_LOCK: Duration = Duration::from_secs(15 * 60);
/// Strikes are forgotten this long after the last failure.
const FORGET: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug)]
struct Strikes {
    fails: u32,
    last: Instant,
    locked_until: Option<Instant>,
}

/// Failed-login bookkeeping per username (lower case) and per address.
#[derive(Default)]
pub struct LoginGuard {
    users: HashMap<String, Strikes>,
    ips: HashMap<IpAddr, Strikes>,
}

/// Lockout after `fails` failures: none for the first `free`, then
/// [`BASE_LOCK`] doubling with every further failure.
fn lock_for(fails: u32, free: u32) -> Option<Duration> {
    let over = fails.checked_sub(free + 1)?;
    let d = BASE_LOCK.saturating_mul(1u32 << over.min(10));
    Some(d.min(MAX_LOCK))
}

fn strike(s: &mut Strikes, free: u32, now: Instant) {
    s.fails = s.fails.saturating_add(1);
    s.last = now;
    s.locked_until = lock_for(s.fails, free).map(|d| now + d);
}

fn remaining(s: Option<&Strikes>, now: Instant) -> Option<Duration> {
    s.and_then(|s| s.locked_until)
        .filter(|&t| t > now)
        .map(|t| t - now)
}

impl LoginGuard {
    fn sweep(&mut self, now: Instant) {
        if self.users.len() + self.ips.len() > 100_000 {
            self.users
                .retain(|_, s| now.duration_since(s.last) < FORGET);
            self.ips.retain(|_, s| now.duration_since(s.last) < FORGET);
        }
    }

    fn fresh(s: Option<&Strikes>, now: Instant) -> Option<&Strikes> {
        s.filter(|s| now.duration_since(s.last) < FORGET)
    }

    /// `Err(wait)` while `user` or `ip` is locked out.
    pub fn check_at(&self, user: &str, ip: Option<IpAddr>, now: Instant) -> Result<(), Duration> {
        let u = remaining(Self::fresh(self.users.get(user), now), now);
        let i = ip.and_then(|ip| remaining(Self::fresh(self.ips.get(&ip), now), now));
        match u.max(i) {
            Some(d) => Err(d),
            None => Ok(()),
        }
    }

    pub fn fail_at(&mut self, user: &str, ip: Option<IpAddr>, now: Instant) {
        self.sweep(now);
        let blank = Strikes {
            fails: 0,
            last: now,
            locked_until: None,
        };
        let u = self.users.entry(user.to_string()).or_insert(blank);
        if now.duration_since(u.last) >= FORGET {
            *u = blank;
        }
        strike(u, USER_FREE, now);
        if let Some(ip) = ip {
            let i = self.ips.entry(ip).or_insert(blank);
            if now.duration_since(i.last) >= FORGET {
                *i = blank;
            }
            strike(i, IP_FREE, now);
        }
    }

    /// A correct password clears the username's strikes (the address keeps
    /// its own: one good account does not unlock guessing others).
    pub fn success(&mut self, user: &str) {
        self.users.remove(user);
    }
}

fn locked_out(wait: Duration) -> Response {
    err(
        429,
        &format!(
            "TOO MANY ATTEMPTS: TRY AGAIN IN {} S",
            wait.as_secs().max(1)
        ),
    )
}

/// A string field, untouched (passwords keep their spaces); `max` chars
/// at most or it is refused as missing.
fn field<'a>(v: &'a Value, k: &str, max: usize) -> Option<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| s.chars().count() <= max)
}

fn session(a: &Account, key: String) -> Res {
    ok(&Session {
        id: a.id,
        key,
        username: a.username.clone().unwrap_or_default(),
        profile: a.info(),
    })
}

fn name_error(e: NameError) -> Response {
    match e {
        NameError::Taken => err(409, "USERNAME TAKEN"),
        NameError::AlreadyNamed => err(409, "THIS ACCOUNT ALREADY HAS A USERNAME"),
    }
}

/// Validated `username` + `password` of a register / claim body.
fn new_credentials(v: &Value) -> Result<(String, String), Response> {
    let username = field(v, "username", 64).unwrap_or("").to_string();
    if let Some(e) = username_error(&username) {
        return Err(err(400, e));
    }
    let password = field(v, "password", 1024).unwrap_or("").to_string();
    if let Some(e) = password_error(&password) {
        return Err(err(400, e));
    }
    Ok((username, password))
}

fn hash(password: &str) -> Result<String, Response> {
    password::hash_account(password).ok_or_else(|| {
        log::error!("accounts: password hashing failed");
        err(500, "internal error")
    })
}

impl Api {
    /// `/v1/account/*` (API 5 clients only).
    pub(super) fn account(&self, req: &Request, v: &Value, op: &str) -> Res {
        if crate::compat::is_legacy(req.api) {
            return Err(err(404, "UPDATE YOUR GAME TO USE ACCOUNTS"));
        }
        match op {
            "register" => self.account_register(v),
            "login" => self.account_login(req, v),
            "claim" => self.account_claim(req, v),
            "info" => {
                let mut s = lock(&self.store);
                let a = self.auth(&mut s, req, v)?;
                ok(&AccountInfo {
                    id: a.id,
                    username: a.username.clone().unwrap_or_default(),
                    sessions: db(s.sessions(a.id))?,
                    profile: a.info(),
                })
            }
            "password" => self.account_password(req, v),
            "logout" | "logout_all" => {
                let mut s = lock(&self.store);
                let a = self.auth(&mut s, req, v)?;
                if a.username.is_none() {
                    // its key is all there is: revoking it would lose the account
                    return Err(err(409, "THIS ACCOUNT HAS NO PASSWORD YET: CLAIM IT FIRST"));
                }
                if op == "logout" {
                    let key = super::request_key(req, v).unwrap_or_default();
                    db(s.revoke_key(a.id, &key))?;
                } else {
                    db(s.revoke_all(a.id))?;
                    log::info!("accounts: {} logged out everywhere", a.id);
                }
                ok(&json!({ "ok": true }))
            }
            _ => Err(err(404, "no such route")),
        }
    }

    fn account_register(&self, v: &Value) -> Res {
        let (username, password) = new_credentials(v)?;
        {
            let s = lock(&self.store);
            if db(s.account_count())? >= 1_000_000 {
                return Err(err(409, "server full"));
            }
            if db(s.username_taken(&username))? {
                return Err(name_error(NameError::Taken));
            }
        }
        let phc = hash(&password)?;
        let mut s = lock(&self.store);
        let (a, key) = db(s.register_named(&username, &phc))?.map_err(name_error)?;
        log::info!("accounts: {} registered as {username}", a.id);
        session(&a, key)
    }

    fn account_login(&self, req: &Request, v: &Value) -> Res {
        let username = field(v, "username", 64).unwrap_or("");
        let user = username.to_ascii_lowercase();
        let now = Instant::now();
        lock(&self.logins)
            .check_at(&user, req.ip, now)
            .map_err(locked_out)?;
        let password = field(v, "password", rugen_proto::account::PASSWORD_MAX);
        let creds = if username_error(username).is_none() {
            db(lock(&self.store).credentials(username))?
        } else {
            None
        };
        // unknown names and absurd passwords cost a (dummy) check too
        let good = match password {
            Some(pw) => password::verify_account(pw, creds.as_ref().and_then(|c| c.1.as_deref())),
            None => {
                let _ = password::verify_account("", None);
                false
            }
        };
        let Some((id, _)) = creds.filter(|_| good) else {
            lock(&self.logins).fail_at(&user, req.ip, Instant::now());
            return Err(err(401, WRONG));
        };
        lock(&self.logins).success(&user);
        let mut s = lock(&self.store);
        let key = db(s.issue_key(id))?;
        let a = db(s.by_id(id))?.ok_or_else(|| err(401, WRONG))?;
        self.note_seen(a.id);
        session(&a, key)
    }

    fn account_claim(&self, req: &Request, v: &Value) -> Res {
        let a = self.me(req, v)?;
        if a.username.is_some() {
            return Err(name_error(NameError::AlreadyNamed));
        }
        let (username, password) = new_credentials(v)?;
        if db(lock(&self.store).username_taken(&username))? {
            return Err(name_error(NameError::Taken));
        }
        let phc = hash(&password)?;
        let mut s = lock(&self.store);
        let a = db(s.claim(a.id, &username, &phc))?.map_err(name_error)?;
        log::info!("accounts: {} claimed as {username}", a.id);
        let key = super::request_key(req, v).unwrap_or_default();
        session(&a, key)
    }

    /// Change the password (the current one is required): every other key
    /// of the account is revoked; this device gets a fresh one.
    fn account_password(&self, req: &Request, v: &Value) -> Res {
        let a = self.me(req, v)?;
        let Some(username) = a.username.clone() else {
            return Err(err(409, "THIS ACCOUNT HAS NO PASSWORD YET: CLAIM IT FIRST"));
        };
        let user = username.to_ascii_lowercase();
        lock(&self.logins)
            .check_at(&user, req.ip, Instant::now())
            .map_err(locked_out)?;
        let new = field(v, "new_password", 1024).unwrap_or("");
        if let Some(e) = password_error(new) {
            return Err(err(400, e));
        }
        let old = field(v, "password", rugen_proto::account::PASSWORD_MAX).unwrap_or("");
        let phc = db(lock(&self.store).password_of(a.id))?;
        if !password::verify_account(old, phc.as_deref()) {
            lock(&self.logins).fail_at(&user, req.ip, Instant::now());
            return Err(err(401, "WRONG PASSWORD"));
        }
        lock(&self.logins).success(&user);
        let phc = hash(new)?;
        let mut s = lock(&self.store);
        db(s.set_password(a.id, &phc))?;
        db(s.revoke_all(a.id))?;
        let key = db(s.issue_key(a.id))?;
        log::info!(
            "accounts: {} changed the password (other devices logged out)",
            a.id
        );
        session(&a, key)
    }

    /// Operator reset (`/v1/admin/reset_password`, `--reset-password`): a
    /// temporary password, every key revoked. Returns (username, password).
    pub fn reset_password(&self, username: &str) -> Result<(String, String), Response> {
        let a = db(lock(&self.store).by_username(username))?
            .ok_or_else(|| err(404, "no such username"))?;
        let temp = password::temporary();
        let phc = hash(&temp)?;
        let mut s = lock(&self.store);
        db(s.set_password(a.id, &phc))?;
        db(s.revoke_all(a.id))?;
        let name = a.username.unwrap_or_default();
        log::warn!("admin: password of {name} ({}) reset", a.id);
        Ok((name, temp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockouts_grow_and_expire() {
        let mut g = LoginGuard::default();
        let t0 = Instant::now();
        let ip: Option<IpAddr> = Some("10.0.0.1".parse().unwrap());
        for _ in 0..USER_FREE - 1 {
            g.fail_at("axel", ip, t0);
            assert!(g.check_at("axel", ip, t0).is_ok());
        }
        // the 5th failure locks the name for 30 s
        g.fail_at("axel", ip, t0);
        assert!(g.check_at("axel", ip, t0).is_ok(), "5 free tries");
        g.fail_at("axel", ip, t0);
        assert_eq!(g.check_at("axel", ip, t0), Err(BASE_LOCK));
        // other names from another address are not affected
        assert!(g.check_at("bob", None, t0).is_ok());
        let t1 = t0 + BASE_LOCK;
        assert!(g.check_at("axel", ip, t1).is_ok());
        g.fail_at("axel", ip, t1);
        assert_eq!(g.check_at("axel", ip, t1), Err(BASE_LOCK * 2), "doubles");
        // capped
        let mut t = t1;
        for _ in 0..20 {
            g.fail_at("axel", None, t);
            t += Duration::from_secs(1);
        }
        assert!(g.check_at("axel", None, t).unwrap_err() <= MAX_LOCK);
        // forgotten after an hour without failures
        assert!(g.check_at("axel", None, t + FORGET).is_ok());
        g.fail_at("axel", None, t + FORGET);
        assert!(g.check_at("axel", None, t + FORGET).is_ok(), "fresh count");
        // success clears the name
        g.success("axel");
        assert!(!g.users.contains_key("axel"));
    }

    #[test]
    fn one_address_guessing_many_names_is_locked_out() {
        let mut g = LoginGuard::default();
        let t = Instant::now();
        let ip: Option<IpAddr> = Some("10.0.0.2".parse().unwrap());
        for i in 0..=IP_FREE {
            g.fail_at(&format!("user{i}"), ip, t);
        }
        assert!(g.check_at("someone_else", ip, t).is_err());
        assert!(g.check_at("someone_else", None, t).is_ok());
    }
}
