use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
// Same bound as the Pro server: a longer id is not a normal RustDesk id or hostname,
// and every peer entry and punch-request record keeps its own copy.
pub const MAX_PEER_ID_LEN: usize = 253;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
    // SimpleDesk: unix seconds of the last user input the device told in its heartbeat.
    pub(crate) last_input: Option<u64>,
    // SimpleDesk: unix seconds the device was last seen (heartbeat or end of its connection),
    // 0 if not since hbbs started; the database keeps it too.
    pub(crate) last_seen: u64,
    // SimpleDesk: when last_seen was last written to the database.
    pub(crate) last_seen_saved: u64,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
            last_input: None,
            last_seen: 0,
            last_seen_saved: 0,
        }
    }
}

impl Peer {
    /// Whether the device is online: it registered within REG_TIMEOUT.
    pub(crate) fn is_online(&self) -> bool {
        (self.last_reg_time.elapsed().as_millis() as i64) < crate::rendezvous_server::REG_TIMEOUT
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
    // SimpleDesk: settings for signed-in users, shared by hbbs and the web panel.
    pub(crate) accounts: Arc<crate::accounts::Accounts>,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = get_arg_opt("DB_URL").unwrap_or_else(|| {
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
            accounts: Arc::new(crate::accounts::Accounts::from_args()),
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    /// SimpleDesk: renames a device in memory and in the database.
    /// The caller has checked that the device owns old_id and that new_id is free.
    pub(crate) async fn change_id(
        &self,
        peer: LockPeer,
        old_id: &str,
        new_id: &str,
    ) -> register_pk_response::Result {
        let (guid, pk, info_str) = {
            let peer = peer.read().await;
            (
                peer.guid.clone(),
                peer.pk.clone(),
                serde_json::to_string(&peer.info).unwrap_or_default(),
            )
        };
        if !guid.is_empty() {
            if let Err(err) = self.db.update_pk(&guid, new_id, &pk, &info_str).await {
                log::error!("db.update_pk failed while changing id: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
        }
        let mut map = self.map.write().await;
        map.remove(old_id);
        map.insert(new_id.to_owned(), peer);
        log::info!("id changed from {} to {}", old_id, new_id);
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    /// SimpleDesk: deletes a device from the database and from memory. A device that still
    /// runs registers again later, as a new device. False if there is no such device.
    pub(crate) async fn delete_device(&self, id: &str) -> ResultType<bool> {
        let deleted = self.db.delete_device(id).await?;
        self.map.write().await.remove(id);
        Ok(deleted)
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }
}

/// SimpleDesk tests: a PeerMap on its own database in `dir`. PeerMap::new reads DB_URL from
/// the environment, which all tests share, so creating one is serialized.
#[cfg(test)]
pub(crate) async fn test_peer_map(dir: &tempfile::TempDir) -> PeerMap {
    lazy_static::lazy_static! {
        static ref TEST_DB_LOCK: Mutex<()> = Mutex::new(());
    }
    let _guard = TEST_DB_LOCK.lock().await;
    std::env::set_var("DB_URL", dir.path().join("db_v2.sqlite3"));
    PeerMap::new().await.unwrap()
}
