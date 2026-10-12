//! Short-lived TURN credentials from Cloudflare Realtime TURN
//! (<https://developers.cloudflare.com/realtime/turn/>): the long-term key
//! stays on the server, clients get a username / credential pair valid for
//! [`TTL_SECS`].

use std::time::{Duration, Instant};

use rugen_proto::TurnCredentials;
use serde::Deserialize;

pub const TTL_SECS: u64 = 4 * 3600;

pub struct CfTurn {
    key_id: String,
    token: String,
    /// One credential set is shared until half its lifetime is gone.
    cache: std::sync::Mutex<Option<(TurnCredentials, Instant)>>,
}

#[derive(Deserialize)]
struct IceServer {
    #[serde(default)]
    urls: UrlList,
    #[serde(default)]
    username: String,
    #[serde(default)]
    credential: String,
}

#[derive(Deserialize, Default)]
#[serde(untagged)]
enum UrlList {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IceServers {
    Many(Vec<IceServer>),
    One(IceServer),
}

#[derive(Deserialize)]
struct Generated {
    #[serde(rename = "iceServers")]
    ice_servers: IceServers,
}

/// Pick the TURN entry out of a generate-ice-servers reply.
pub fn parse(body: &str) -> Result<TurnCredentials, String> {
    let g: Generated = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let list = match g.ice_servers {
        IceServers::Many(v) => v,
        IceServers::One(s) => vec![s],
    };
    for s in list {
        let urls = match s.urls {
            UrlList::One(u) => vec![u],
            UrlList::Many(v) => v,
            UrlList::None => vec![],
        };
        let turn: Vec<String> = urls
            .into_iter()
            .filter(|u| u.starts_with("turn:") || u.starts_with("turns:"))
            // port 53 is often filtered; skip it like the Cloudflare docs suggest
            .filter(|u| !u.contains(":53?") && !u.ends_with(":53"))
            .collect();
        if !turn.is_empty() && !s.username.is_empty() {
            return Ok(TurnCredentials {
                urls: turn,
                username: s.username,
                credential: s.credential,
            });
        }
    }
    Err("no TURN server in the reply".into())
}

impl CfTurn {
    pub fn new(key_id: String, token: String) -> Self {
        Self {
            key_id,
            token,
            cache: std::sync::Mutex::new(None),
        }
    }

    /// Cached or freshly minted credentials (blocking HTTPS call).
    pub fn credentials(&self) -> Result<TurnCredentials, String> {
        if let Ok(c) = self.cache.lock()
            && let Some((creds, at)) = c.as_ref()
            && at.elapsed() < Duration::from_secs(TTL_SECS / 2)
        {
            return Ok(creds.clone());
        }
        let url = format!(
            "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate-ice-servers",
            self.key_id
        );
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(8)))
            .http_status_as_error(false)
            .build()
            .into();
        let mut resp = agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .send_json(serde_json::json!({ "ttl": TTL_SECS }))
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&status) {
            return Err(format!("cloudflare turn: http {status}"));
        }
        let creds = parse(&body)?;
        if let Ok(mut c) = self.cache.lock() {
            *c = Some((creds.clone(), Instant::now()));
        }
        Ok(creds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_reply() {
        let body = r#"{"iceServers":[
            {"urls":["stun:stun.cloudflare.com:3478","stun:stun.cloudflare.com:53"]},
            {"urls":["turn:turn.cloudflare.com:3478?transport=udp",
                     "turn:turn.cloudflare.com:53?transport=udp",
                     "turns:turn.cloudflare.com:443?transport=tcp"],
             "username":"u1","credential":"c1"}]}"#;
        let c = parse(body).unwrap();
        assert_eq!(c.username, "u1");
        assert_eq!(c.credential, "c1");
        assert_eq!(
            c.urls,
            vec![
                "turn:turn.cloudflare.com:3478?transport=udp".to_string(),
                "turns:turn.cloudflare.com:443?transport=tcp".to_string()
            ]
        );
        // older single-object form
        let old = r#"{"iceServers":{"urls":"turn:t:3478","username":"u","credential":"c"}}"#;
        assert_eq!(parse(old).unwrap().urls, vec!["turn:t:3478".to_string()]);
        assert!(parse(r#"{"iceServers":[]}"#).is_err());
    }
}
