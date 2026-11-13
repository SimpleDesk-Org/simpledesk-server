use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = crate::common::get_arg_or("MAX_DATABASE_CONNECTIONS", "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        db.create_panel_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    // SimpleDesk: tables and queries of the web panel. They use sqlx::query without the
    // compile-time checked macros, so building needs no sample database.

    async fn create_panel_tables(&self) -> ResultType<()> {
        for statement in [
            "create table if not exists panel_user (
                name varchar(100) primary key not null,
                password_hash text not null,
                created_at datetime not null default(current_timestamp)
            )",
            // Tokens of logged-in clients, stored only as a hash.
            "create table if not exists api_token (
                token_hash varchar(64) primary key not null,
                user varchar(100) not null,
                device_id varchar(100) not null default '',
                created_at datetime not null default(current_timestamp)
            )",
            // Address books; every user has one personal book.
            "create table if not exists ab (
                guid varchar(36) primary key not null,
                owner varchar(100) not null,
                name varchar(100) not null,
                personal integer not null default 0
            )",
            "create unique index if not exists index_ab_personal on ab (owner) where personal = 1",
            // Entries as the JSON object the client sends (id, alias, tags, note, hash, ...).
            "create table if not exists ab_peer (
                ab varchar(36) not null,
                id varchar(100) not null,
                data text not null,
                primary key (ab, id)
            )",
            "create table if not exists ab_tag (
                ab varchar(36) not null,
                name varchar(100) not null,
                color integer not null,
                primary key (ab, name)
            )",
            // Logins in the web panel, stored only as a hash.
            "create table if not exists panel_session (
                token_hash varchar(64) primary key not null,
                user varchar(100) not null,
                created_at datetime not null default(current_timestamp),
                last_used datetime
            )",
            // Groups of users; members may control the devices of their group.
            "create table if not exists user_group (
                name varchar(100) primary key not null collate nocase,
                created_at datetime not null default(current_timestamp)
            )",
            "create table if not exists user_group_member (
                grp varchar(100) not null,
                user varchar(100) not null,
                primary key (grp, user)
            )",
            // Who a device belongs to: a user and/or a group, '' for none. By guid, so a
            // device keeps its owner when its ID changes.
            "create table if not exists device_owner (
                guid blob primary key not null,
                owner varchar(100) not null default '',
                grp varchar(100) not null default ''
            )",
            // The client tells books apart by name, so shared books have unique names.
            "create unique index if not exists index_ab_shared_name on ab (name collate nocase) where personal = 0",
            // Who may use a shared book: kind 'user' or 'group', rule 1 lesen, 2 schreiben,
            // 3 voll (as ShareRule in the client).
            "create table if not exists ab_rule (
                ab varchar(36) not null,
                kind varchar(10) not null,
                name varchar(100) not null,
                rule integer not null,
                primary key (ab, kind, name)
            )",
            // When a device (by guid) was last seen, in unix seconds, for "Offline seit".
            "create table if not exists device_seen (
                guid blob primary key not null,
                last_seen integer not null
            )",
            // The page "Protokoll": connections, files, alarms and changes by admins. Times are
            // unix seconds. kind: conn, file, alarm or admin. user: who connected (signed in
            // on the controlling device) or who changed something. peer_*: the controlling
            // device. A connection row gets ended_at when it closes.
            "create table if not exists audit_log (
                id integer primary key autoincrement,
                created_at integer not null,
                kind varchar(10) not null,
                device_guid blob,
                device_id varchar(100) not null default '',
                user varchar(100) not null default '',
                peer_id varchar(100) not null default '',
                peer_name varchar(100) not null default '',
                ip varchar(64) not null default '',
                conn_id integer not null default 0,
                authorized integer not null default 0,
                ended_at integer,
                detail text not null default ''
            )",
            "create index if not exists index_audit_created on audit_log (created_at)",
            "create index if not exists index_audit_conn on audit_log (device_guid, conn_id)",
        ] {
            sqlx::query(statement)
                .execute(self.pool.get().await?.deref_mut())
                .await?;
        }
        self.add_column("api_token", "last_used", "datetime").await?;
        self.add_column("panel_user", "last_login", "datetime").await?;
        self.add_column("panel_user", "blocked", "integer not null default 0").await?;
        self.create_id_tables().await?;
        // "Zentrale Einstellungen": options for all devices (scope 'all', target ''), a group
        // (scope 'group', target the group name) or a device (scope 'device', target its uuid
        // in hex). Devices get them with the heartbeat.
        sqlx::query(
            "create table if not exists strategy_option (
                scope varchar(10) not null,
                target varchar(100) not null collate nocase,
                key varchar(64) not null,
                value text not null,
                primary key (scope, target, key)
            )",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        // Tokens for setting up devices from the command line (--assign), stored only as a
        // hash. Times are unix seconds.
        sqlx::query(
            "create table if not exists deploy_token (
                id integer primary key autoincrement,
                token_hash varchar(64) not null unique,
                created_by varchar(100) not null,
                created_at integer not null,
                expires_at integer not null,
                note varchar(100) not null default '',
                uses integer not null default 0
            )",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    /// The IDs admins give devices (IDS_BY_ADMIN) and what devices tell about themselves.
    async fn create_id_tables(&self) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let fresh = sqlx::query_scalar::<_, String>(
            "select name from sqlite_master where type = 'table' and name = 'device_id'",
        )
        .fetch_optional(conn.deref_mut())
        .await?
        .is_none();
        for statement in [
            // The ID each device (by uuid) shall have. A device whose current ID differs
            // takes this one with its next heartbeat.
            "create table if not exists device_id (
                uuid blob primary key not null,
                assigned_id varchar(100) not null,
                assigned_at datetime not null default(current_timestamp)
            )",
            // The last system info of a device (hostname, username, os, ...), as JSON.
            "create table if not exists device_info (
                uuid blob primary key not null,
                data text not null,
                updated_at datetime not null default(current_timestamp)
            )",
        ] {
            sqlx::query(statement).execute(conn.deref_mut()).await?;
        }
        if fresh {
            // Devices that are here before admins give IDs keep the ID they have. With two
            // rows for one uuid the newest wins.
            let done = sqlx::query(
                "insert or ignore into device_id(uuid, assigned_id)
                 select uuid, id from peer where length(uuid) > 0 order by created_at desc",
            )
            .execute(conn.deref_mut())
            .await?;
            log::info!("SimpleDesk: {} registered devices keep their ID", done.rows_affected());
        }
        Ok(())
    }

    /// The ID an admin gave the device with this uuid, None if none yet.
    pub async fn id_assignment(&self, uuid: &[u8]) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>("select assigned_id from device_id where uuid = ?")
            .bind(uuid)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// For a registered device ID: the ID an admin gave its device (None if none yet).
    /// None outside if no device has this ID.
    pub async fn id_assignment_of(&self, id: &str) -> ResultType<Option<Option<String>>> {
        Ok(sqlx::query_scalar::<_, Option<String>>(
            "select d.assigned_id from peer p left join device_id d on d.uuid = p.uuid where p.id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn set_id_assignment(&self, uuid: &[u8], id: &str) -> ResultType<()> {
        sqlx::query("insert or replace into device_id(uuid, assigned_id) values(?, ?)")
            .bind(uuid)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The uuid of the registered device with this ID.
    pub async fn device_uuid(&self, id: &str) -> ResultType<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar::<_, Vec<u8>>("select uuid from peer where id = ?")
            .bind(id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// Whether another device (another uuid) has this ID or is about to get it. Upper and
    /// lower case do not count as different.
    pub async fn id_taken(&self, id: &str, uuid: &[u8]) -> ResultType<bool> {
        Ok(sqlx::query_scalar::<_, i64>(
            "select 1 from peer where id = ? collate nocase and uuid != ?
             union all select 1 from device_id where assigned_id = ? collate nocase and uuid != ?",
        )
        .bind(id)
        .bind(uuid)
        .bind(id)
        .bind(uuid)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?
        .is_some())
    }

    /// Stores what a registered device tells about itself; false if no device with this
    /// ID and uuid is registered.
    pub async fn save_device_info(&self, id: &str, uuid: &[u8], data: &str) -> ResultType<bool> {
        let done = sqlx::query(
            "insert or replace into device_info(uuid, data)
             select uuid, ? from peer where id = ? and uuid = ?",
        )
        .bind(data)
        .bind(id)
        .bind(uuid)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Tests: forget all given IDs, as in a database from before IDS_BY_ADMIN.
    #[cfg(test)]
    pub async fn drop_id_tables(&self) -> ResultType<()> {
        sqlx::query("drop table device_id")
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Adds a column to a table of an older database. SQLite has no "add column if not exists".
    async fn add_column(&self, table: &str, column: &str, definition: &str) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let columns = sqlx::query_scalar::<_, String>(&format!(
            "select name from pragma_table_info('{}')",
            table
        ))
        .fetch_all(conn.deref_mut())
        .await?;
        if !columns.iter().any(|name| name == column) {
            sqlx::query(&format!("alter table {} add column {} {}", table, column, definition))
                .execute(conn.deref_mut())
                .await?;
        }
        Ok(())
    }

    pub async fn insert_api_token(&self, token_hash: &str, user: &str, device_id: &str) -> ResultType<()> {
        sqlx::query("insert into api_token(token_hash, user, device_id) values(?, ?, ?)")
            .bind(token_hash)
            .bind(user)
            .bind(device_id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The user of a token that is younger than `max_age_days`, if its user still exists.
    /// Notes the use, at most once a minute.
    pub async fn get_api_token_user(&self, token_hash: &str, max_age_days: i64) -> ResultType<Option<String>> {
        let mut conn = self.pool.get().await?;
        let user = sqlx::query_scalar::<_, String>(
            "select t.user from api_token t join panel_user u on u.name = t.user
             where t.token_hash = ? and t.created_at > datetime('now', ?) and u.blocked = 0",
        )
        .bind(token_hash)
        .bind(format!("-{} days", max_age_days))
        .fetch_optional(conn.deref_mut())
        .await?;
        if user.is_some() {
            sqlx::query(
                "update api_token set last_used = current_timestamp
                 where token_hash = ? and (last_used is null or last_used < datetime('now', '-1 minutes'))",
            )
            .bind(token_hash)
            .execute(conn.deref_mut())
            .await?;
        }
        Ok(user)
    }

    pub async fn delete_api_token(&self, token_hash: &str) -> ResultType<()> {
        sqlx::query("delete from api_token where token_hash = ?")
            .bind(token_hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn insert_panel_session(&self, token_hash: &str, user: &str) -> ResultType<()> {
        sqlx::query("insert into panel_session(token_hash, user) values(?, ?)")
            .bind(token_hash)
            .bind(user)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The user of a panel session that is younger than `max_age_hours`, if its user still
    /// exists. Notes the use, at most once a minute.
    pub async fn get_panel_session_user(&self, token_hash: &str, max_age_hours: i64) -> ResultType<Option<String>> {
        let mut conn = self.pool.get().await?;
        let user = sqlx::query_scalar::<_, String>(
            "select s.user from panel_session s join panel_user u on u.name = s.user
             where s.token_hash = ? and s.created_at > datetime('now', ?) and u.blocked = 0",
        )
        .bind(token_hash)
        .bind(format!("-{} hours", max_age_hours))
        .fetch_optional(conn.deref_mut())
        .await?;
        if user.is_some() {
            sqlx::query(
                "update panel_session set last_used = current_timestamp
                 where token_hash = ? and (last_used is null or last_used < datetime('now', '-1 minutes'))",
            )
            .bind(token_hash)
            .execute(conn.deref_mut())
            .await?;
        }
        Ok(user)
    }

    pub async fn delete_panel_session(&self, token_hash: &str) -> ResultType<()> {
        sqlx::query("delete from panel_session where token_hash = ?")
            .bind(token_hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Removes tokens and panel sessions that are too old to be used anyway.
    pub async fn delete_expired_logins(&self, token_days: i64, session_hours: i64) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        sqlx::query("delete from api_token where created_at <= datetime('now', ?)")
            .bind(format!("-{} days", token_days))
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("delete from panel_session where created_at <= datetime('now', ?)")
            .bind(format!("-{} hours", session_hours))
            .execute(conn.deref_mut())
            .await?;
        Ok(())
    }

    /// Tests: moves the logins of a user `hours` into the past.
    #[cfg(test)]
    pub async fn age_logins(&self, user: &str, hours: i64) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        for table in ["api_token", "panel_session"] {
            sqlx::query(&format!(
                "update {} set created_at = datetime(created_at, ?) where user = ?",
                table
            ))
            .bind(format!("-{} hours", hours))
            .bind(user)
            .execute(conn.deref_mut())
            .await?;
        }
        Ok(())
    }

    /// The guid of the user's personal address book, created on first use.
    pub async fn personal_ab(&self, owner: &str) -> ResultType<String> {
        let mut conn = self.pool.get().await?;
        let existing = sqlx::query_scalar::<_, String>(
            "select guid from ab where owner = ? and personal = 1",
        )
        .bind(owner)
        .fetch_optional(conn.deref_mut())
        .await?;
        if let Some(guid) = existing {
            return Ok(guid);
        }
        let guid = uuid::Uuid::new_v4().to_string();
        sqlx::query("insert into ab(guid, owner, name, personal) values(?, ?, 'Mein Adressbuch', 1)")
            .bind(&guid)
            .bind(owner)
            .execute(conn.deref_mut())
            .await?;
        Ok(guid)
    }

    /// An address book, personal or shared.
    pub async fn get_ab(&self, guid: &str) -> ResultType<Option<AbRow>> {
        let row = sqlx::query_as::<_, (String, String, String, i64)>(
            "select guid, owner, name, personal from ab where guid = ?",
        )
        .bind(guid)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row.map(|(guid, owner, name, personal)| AbRow {
            guid,
            owner,
            name,
            personal: personal != 0,
        }))
    }

    /// All shared books with the best rule `user` has on each through a share for the user
    /// or one of the user's groups (0 for none), sorted by name.
    pub async fn shared_abs_for(&self, user: &str) -> ResultType<Vec<(AbRow, i64)>> {
        let rows = sqlx::query_as::<_, (String, String, String, i64)>(
            "select a.guid, a.owner, a.name, coalesce((select max(r.rule) from ab_rule r where r.ab = a.guid
                and ((r.kind = 'user' and r.name = ?)
                  or (r.kind = 'group' and r.name in (select grp from user_group_member where user = ?)))), 0)
             from ab a where a.personal = 0 order by a.name collate nocase",
        )
        .bind(user)
        .bind(user)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(guid, owner, name, rule)| {
                let row = AbRow {
                    guid,
                    owner,
                    name,
                    personal: false,
                };
                (row, rule)
            })
            .collect())
    }

    /// A new shared book; None if a shared book with that name (in any case) exists.
    pub async fn create_shared_ab(&self, owner: &str, name: &str) -> ResultType<Option<String>> {
        let guid = uuid::Uuid::new_v4().to_string();
        let done = sqlx::query("insert or ignore into ab(guid, owner, name, personal) values(?, ?, ?, 0)")
            .bind(&guid)
            .bind(owner)
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok((done.rows_affected() > 0).then(|| guid))
    }

    /// Renames a shared book; false if another shared book has that name.
    pub async fn rename_shared_ab(&self, guid: &str, name: &str) -> ResultType<bool> {
        let done = sqlx::query("update or ignore ab set name = ? where guid = ? and personal = 0")
            .bind(name)
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Deletes a shared book with its entries, tags and shares.
    pub async fn delete_shared_ab(&self, guid: &str) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        for statement in [
            "delete from ab_peer where ab = ?",
            "delete from ab_tag where ab = ?",
            "delete from ab_rule where ab = ?",
            "delete from ab where guid = ? and personal = 0",
        ] {
            sqlx::query(statement)
                .bind(guid)
                .execute(conn.deref_mut())
                .await?;
        }
        Ok(())
    }

    /// The shares of a book as (kind, name, rule), groups first.
    pub async fn ab_rules(&self, guid: &str) -> ResultType<Vec<(String, String, i64)>> {
        Ok(sqlx::query_as::<_, (String, String, i64)>(
            "select kind, name, rule from ab_rule where ab = ? order by kind, name collate nocase",
        )
        .bind(guid)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn set_ab_rule(&self, guid: &str, kind: &str, name: &str, rule: i64) -> ResultType<()> {
        sqlx::query("insert or replace into ab_rule(ab, kind, name, rule) values(?, ?, ?, ?)")
            .bind(guid)
            .bind(kind)
            .bind(name)
            .bind(rule)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn delete_ab_rule(&self, guid: &str, kind: &str, name: &str) -> ResultType<()> {
        sqlx::query("delete from ab_rule where ab = ? and kind = ? and name = ?")
            .bind(guid)
            .bind(kind)
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The entries of an address book as JSON strings, sorted by id.
    pub async fn list_ab_peers(&self, guid: &str) -> ResultType<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "select data from ab_peer where ab = ? order by id collate nocase",
        )
        .bind(guid)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn get_ab_peer(&self, guid: &str, id: &str) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>("select data from ab_peer where ab = ? and id = ?")
            .bind(guid)
            .bind(id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    pub async fn upsert_ab_peer(&self, guid: &str, id: &str, data: &str) -> ResultType<()> {
        sqlx::query("insert or replace into ab_peer(ab, id, data) values(?, ?, ?)")
            .bind(guid)
            .bind(id)
            .bind(data)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn delete_ab_peer(&self, guid: &str, id: &str) -> ResultType<()> {
        sqlx::query("delete from ab_peer where ab = ? and id = ?")
            .bind(guid)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The tags of an address book as (name, color), sorted by name.
    pub async fn list_ab_tags(&self, guid: &str) -> ResultType<Vec<(String, i64)>> {
        Ok(sqlx::query_as::<_, (String, i64)>(
            "select name, color from ab_tag where ab = ? order by name collate nocase",
        )
        .bind(guid)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn upsert_ab_tag(&self, guid: &str, name: &str, color: i64) -> ResultType<()> {
        sqlx::query("insert or replace into ab_tag(ab, name, color) values(?, ?, ?)")
            .bind(guid)
            .bind(name)
            .bind(color)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn delete_ab_tag(&self, guid: &str, name: &str) -> ResultType<()> {
        sqlx::query("delete from ab_tag where ab = ? and name = ?")
            .bind(guid)
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// A user who signs in through the OIDC provider (Eider). There is no password login, so
    /// the old password_hash column only holds "!". An existing user is kept.
    pub async fn ensure_external_user(&self, name: &str) -> ResultType<()> {
        sqlx::query("insert or ignore into panel_user(name, password_hash) values(?, '!')")
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Notes a login through the provider.
    pub async fn record_login(&self, name: &str) -> ResultType<()> {
        sqlx::query("update panel_user set last_login = current_timestamp where name = ?")
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn is_blocked(&self, name: &str) -> ResultType<bool> {
        Ok(sqlx::query_scalar::<_, i64>("select blocked from panel_user where name = ?")
            .bind(name)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?
            .unwrap_or_default()
            != 0)
    }

    pub async fn set_blocked(&self, name: &str, blocked: bool) -> ResultType<()> {
        sqlx::query("update panel_user set blocked = ? where name = ?")
            .bind(blocked as i64)
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Ends every login of a user: all client tokens and panel sessions.
    pub async fn delete_user_logins(&self, name: &str) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        for statement in [
            "delete from api_token where user = ?",
            "delete from panel_session where user = ?",
        ] {
            sqlx::query(statement)
                .bind(name)
                .execute(conn.deref_mut())
                .await?;
        }
        Ok(())
    }

    /// Everybody who ever signed in, sorted by name.
    pub async fn list_users(&self) -> ResultType<Vec<UserRow>> {
        let rows = sqlx::query_as::<_, (String, String, i64, String, String)>(
            "select u.name, coalesce(cast(u.last_login as text), ''), u.blocked,
                coalesce((select cast(max(last_used) as text) from api_token where user = u.name), ''),
                coalesce((select cast(max(last_used) as text) from panel_session where user = u.name), '')
             from panel_user u order by u.name collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(name, last_login, blocked, token_used, session_used)| UserRow {
                name,
                last_login,
                blocked: blocked != 0,
                last_active: token_used.max(session_used),
            })
            .collect())
    }

    pub async fn user_exists(&self, name: &str) -> ResultType<bool> {
        Ok(sqlx::query_scalar::<_, String>("select name from panel_user where name = ?")
            .bind(name)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?
            .is_some())
    }

    pub async fn list_groups(&self) -> ResultType<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>("select name from user_group order by name collate nocase")
            .fetch_all(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// The stored spelling of a group, None if there is no such group.
    pub async fn group_name(&self, name: &str) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>("select name from user_group where name = ?")
            .bind(name)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// Creates a group; false if a group with that name (in any case) exists.
    pub async fn create_group(&self, name: &str) -> ResultType<bool> {
        let done = sqlx::query("insert or ignore into user_group(name) values(?)")
            .bind(name)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Deletes a group with its members and shares; its devices keep their owner but lose the
    /// group.
    pub async fn delete_group(&self, name: &str) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        for statement in [
            "delete from user_group_member where grp = ?",
            "update device_owner set grp = '' where grp = ?",
            "delete from ab_rule where kind = 'group' and name = ?",
            "delete from strategy_option where scope = 'group' and target = ?",
            "delete from user_group where name = ?",
        ] {
            sqlx::query(statement)
                .bind(name)
                .execute(conn.deref_mut())
                .await?;
        }
        Ok(())
    }

    pub async fn add_group_member(&self, group: &str, user: &str) -> ResultType<()> {
        sqlx::query("insert or ignore into user_group_member(grp, user) values(?, ?)")
            .bind(group)
            .bind(user)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn remove_group_member(&self, group: &str, user: &str) -> ResultType<()> {
        sqlx::query("delete from user_group_member where grp = ? and user = ?")
            .bind(group)
            .bind(user)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// All memberships as (group, user).
    pub async fn list_group_members(&self) -> ResultType<Vec<(String, String)>> {
        Ok(sqlx::query_as::<_, (String, String)>(
            "select grp, user from user_group_member order by grp collate nocase, user collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// The groups a user is a member of, sorted by name.
    pub async fn user_groups(&self, user: &str) -> ResultType<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "select grp from user_group_member where user = ? order by grp collate nocase",
        )
        .bind(user)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// All registered devices with owner, group, the ID an admin gave them and what they
    /// told about themselves, sorted by id.
    pub async fn list_devices(&self) -> ResultType<Vec<DeviceRow>> {
        type Row = (String, String, String, String, String, Option<String>, String, i64);
        let rows = sqlx::query_as::<_, Row>(
            "select p.id, p.info, cast(p.created_at as text), coalesce(o.owner, ''), coalesce(o.grp, ''),
                d.assigned_id, coalesce(i.data, ''), coalesce(s.last_seen, 0)
             from peer p left join device_owner o on o.guid = p.guid
                left join device_id d on d.uuid = p.uuid
                left join device_info i on i.uuid = p.uuid
                left join device_seen s on s.guid = p.guid
             order by p.id collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, info, registered, owner, group, assigned_id, sysinfo, last_seen)| DeviceRow {
                id,
                info,
                registered,
                owner,
                group,
                assigned_id,
                sysinfo,
                last_seen: last_seen.max(0) as u64,
            })
            .collect())
    }

    /// The guid of the registered device with this ID.
    pub async fn device_guid(&self, id: &str) -> ResultType<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar::<_, Vec<u8>>("select guid from peer where id = ?")
            .bind(id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// Adds a row to the log and returns its id.
    pub async fn insert_audit(&self, row: &NewAudit) -> ResultType<i64> {
        let done = sqlx::query(
            "insert into audit_log(created_at, kind, device_guid, device_id, user, peer_id, peer_name,
                ip, conn_id, authorized, detail) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(row.created_at as i64)
        .bind(row.kind)
        .bind(&row.device_guid)
        .bind(&row.device_id)
        .bind(&row.user)
        .bind(&row.peer_id)
        .bind(&row.peer_name)
        .bind(&row.ip)
        .bind(row.conn_id)
        .bind(row.authorized as i64)
        .bind(&row.detail)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(done.last_insert_rowid())
    }

    /// The newest connection of this device with this connection number that has not ended
    /// and began after `since`: its row id and user.
    pub async fn open_audit_conn(&self, device_guid: &[u8], conn_id: i64, since: u64) -> ResultType<Option<(i64, String)>> {
        Ok(sqlx::query_as::<_, (i64, String)>(
            "select id, user from audit_log where kind = 'conn' and device_guid = ? and conn_id = ?
                and ended_at is null and created_at >= ? order by id desc limit 1",
        )
        .bind(device_guid)
        .bind(conn_id)
        .bind(since as i64)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// The controlling device logged in: who it is and what kind of connection.
    pub async fn authorize_audit_conn(&self, id: i64, peer_id: &str, peer_name: &str, detail: &str) -> ResultType<()> {
        sqlx::query("update audit_log set authorized = 1, peer_id = ?, peer_name = ?, detail = ? where id = ?")
            .bind(peer_id)
            .bind(peer_name)
            .bind(detail)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn end_audit_conn(&self, id: i64, ended_at: u64) -> ResultType<()> {
        sqlx::query("update audit_log set ended_at = ? where id = ?")
            .bind(ended_at as i64)
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Deletes rows older than `before` (unix seconds); returns how many.
    pub async fn delete_old_audit(&self, before: u64) -> ResultType<u64> {
        let done = sqlx::query("delete from audit_log where created_at < ?")
            .bind(before as i64)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(done.rows_affected())
    }

    /// The newest rows of the log that match `filter`, at most `limit`.
    pub async fn list_audit(&self, filter: &AuditFilter, limit: i64) -> ResultType<Vec<AuditRow>> {
        enum Arg<'a> {
            Text(&'a str),
            Int(i64),
        }
        let mut sql = String::from(
            "select a.created_at, a.kind, a.device_id, a.user, a.peer_id, a.peer_name, a.ip,
                a.authorized, a.ended_at, a.detail from audit_log a where 1 = 1",
        );
        let mut args = Vec::new();
        if let Some(user) = filter.visible_to.as_deref() {
            // A Benutzer sees the rows of the own devices and of the group's devices, and
            // what the user did.
            sql.push_str(
                " and (a.user = ? or a.device_guid in (select o.guid from device_owner o
                    where o.owner = ? or (o.grp != '' and o.grp in
                        (select grp from user_group_member where user = ?))))",
            );
            args.extend([Arg::Text(user), Arg::Text(user), Arg::Text(user)]);
        }
        if !filter.device.is_empty() {
            sql.push_str(" and a.device_id like '%' || ? || '%'");
            args.push(Arg::Text(&filter.device));
        }
        if !filter.user.is_empty() {
            sql.push_str(" and a.user like '%' || ? || '%'");
            args.push(Arg::Text(&filter.user));
        }
        if let Some(from) = filter.from {
            sql.push_str(" and a.created_at >= ?");
            args.push(Arg::Int(from as i64));
        }
        if let Some(until) = filter.until {
            sql.push_str(" and a.created_at < ?");
            args.push(Arg::Int(until as i64));
        }
        sql.push_str(" order by a.id desc limit ?");
        args.push(Arg::Int(limit));
        type Row = (i64, String, String, String, String, String, String, i64, Option<i64>, String);
        let mut query = sqlx::query_as::<_, Row>(&sql);
        for arg in args {
            query = match arg {
                Arg::Text(text) => query.bind(text),
                Arg::Int(number) => query.bind(number),
            };
        }
        let rows = query.fetch_all(self.pool.get().await?.deref_mut()).await?;
        Ok(rows
            .into_iter()
            .map(
                |(created_at, kind, device_id, user, peer_id, peer_name, ip, authorized, ended_at, detail)| AuditRow {
                    created_at: created_at.max(0) as u64,
                    kind,
                    device_id,
                    user,
                    peer_id,
                    peer_name,
                    ip,
                    authorized: authorized != 0,
                    ended_at: ended_at.map(|ended| ended.max(0) as u64),
                    detail,
                },
            )
            .collect())
    }

    /// Notes when the device with this guid was last seen (unix seconds).
    pub async fn save_last_seen(&self, guid: &[u8], last_seen: u64) -> ResultType<()> {
        sqlx::query("insert or replace into device_seen(guid, last_seen) values(?, ?)")
            .bind(guid)
            .bind(last_seen as i64)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// Owner and group of a device, ('', '') without; None if there is no such device.
    pub async fn device_owner(&self, id: &str) -> ResultType<Option<(String, String)>> {
        Ok(sqlx::query_as::<_, (String, String)>(
            "select coalesce(o.owner, ''), coalesce(o.grp, '')
             from peer p left join device_owner o on o.guid = p.guid where p.id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// Gives a device an owner and a group ('' for none); false if there is no such device.
    pub async fn assign_device(&self, id: &str, owner: &str, group: &str) -> ResultType<bool> {
        let done = sqlx::query(
            "insert into device_owner(guid, owner, grp) select guid, ?, ? from peer where id = ?
             on conflict(guid) do update set owner = excluded.owner, grp = excluded.grp",
        )
        .bind(owner)
        .bind(group)
        .bind(id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The settings of a scope ('all', 'group' or 'device') and target, as (key, value).
    pub async fn strategy_options(&self, scope: &str, target: &str) -> ResultType<Vec<(String, String)>> {
        Ok(sqlx::query_as::<_, (String, String)>(
            "select key, value from strategy_option where scope = ? and target = ? order by key",
        )
        .bind(scope)
        .bind(target)
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// Replaces the settings of a scope and target.
    pub async fn set_strategy_options(&self, scope: &str, target: &str, options: &[(String, String)]) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        let mut tx = conn.begin().await?;
        sqlx::query("delete from strategy_option where scope = ? and target = ?")
            .bind(scope)
            .bind(target)
            .execute(&mut tx)
            .await?;
        for (key, value) in options {
            sqlx::query("insert into strategy_option(scope, target, key, value) values(?, ?, ?, ?)")
                .bind(scope)
                .bind(target)
                .bind(key)
                .bind(value)
                .execute(&mut tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The IDs of the devices that have settings of their own.
    pub async fn devices_with_settings(&self) -> ResultType<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "select distinct p.id from peer p join strategy_option s
                on s.scope = 'device' and s.target = lower(hex(p.uuid))
             order by p.id collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// For the registered device with this ID and uuid: its group ('' for none) and every
    /// setting for all devices, its group and itself, as (scope, key, value). None if no such
    /// device is registered.
    pub async fn device_strategy(&self, id: &str, uuid: &[u8]) -> ResultType<Option<(String, Vec<(String, String, String)>)>> {
        let mut conn = self.pool.get().await?;
        let Some(group) = sqlx::query_scalar::<_, String>(
            "select coalesce(o.grp, '') from peer p left join device_owner o on o.guid = p.guid
             where p.id = ? and p.uuid = ?",
        )
        .bind(id)
        .bind(uuid)
        .fetch_optional(conn.deref_mut())
        .await?
        else {
            return Ok(None);
        };
        let options = sqlx::query_as::<_, (String, String, String)>(
            "select scope, key, value from strategy_option
             where scope = 'all' or (scope = 'group' and target = ? and ? != '')
                or (scope = 'device' and target = lower(hex(?)))",
        )
        .bind(&group)
        .bind(&group)
        .bind(uuid)
        .fetch_all(conn.deref_mut())
        .await?;
        Ok(Some((group, options)))
    }

    pub async fn insert_deploy_token(&self, token_hash: &str, created_by: &str, created_at: u64, expires_at: u64, note: &str) -> ResultType<()> {
        let mut conn = self.pool.get().await?;
        // Tokens that ran out more than a week ago are of no use, also not in the list.
        sqlx::query("delete from deploy_token where expires_at < ?")
            .bind(created_at.saturating_sub(7 * 24 * 3600) as i64)
            .execute(conn.deref_mut())
            .await?;
        sqlx::query("insert into deploy_token(token_hash, created_by, created_at, expires_at, note) values(?, ?, ?, ?, ?)")
            .bind(token_hash)
            .bind(created_by)
            .bind(created_at as i64)
            .bind(expires_at as i64)
            .bind(note)
            .execute(conn.deref_mut())
            .await?;
        Ok(())
    }

    /// Who created the deploy token with this hash, if it is valid at `now`.
    pub async fn deploy_token_creator(&self, token_hash: &str, now: u64) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "select created_by from deploy_token where token_hash = ? and expires_at > ?",
        )
        .bind(token_hash)
        .bind(now as i64)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    /// Counts a device set up with the deploy token with this hash.
    pub async fn count_deploy_use(&self, token_hash: &str) -> ResultType<()> {
        sqlx::query("update deploy_token set uses = uses + 1 where token_hash = ?")
            .bind(token_hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// All deploy tokens, the newest first.
    pub async fn list_deploy_tokens(&self) -> ResultType<Vec<DeployTokenRow>> {
        type Row = (i64, String, i64, i64, String, i64);
        let rows = sqlx::query_as::<_, Row>(
            "select id, created_by, created_at, expires_at, note, uses from deploy_token order by id desc",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, created_by, created_at, expires_at, note, uses)| DeployTokenRow {
                id,
                created_by,
                created_at: created_at.max(0) as u64,
                expires_at: expires_at.max(0) as u64,
                note,
                uses,
            })
            .collect())
    }

    pub async fn delete_deploy_token(&self, id: i64) -> ResultType<()> {
        sqlx::query("delete from deploy_token where id = ?")
            .bind(id)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The shared address book with this name (upper and lower case do not matter).
    pub async fn shared_ab_by_name(&self, name: &str) -> ResultType<Option<AbRow>> {
        let row = sqlx::query_as::<_, (String, String, String)>(
            "select guid, owner, name from ab where personal = 0 and name = ? collate nocase",
        )
        .bind(name)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row.map(|(guid, owner, name)| AbRow {
            guid,
            owner,
            name,
            personal: false,
        }))
    }

    /// The names of all shared address books.
    pub async fn shared_ab_names(&self) -> ResultType<Vec<String>> {
        Ok(sqlx::query_scalar::<_, String>("select name from ab where personal = 0 order by name collate nocase")
            .fetch_all(self.pool.get().await?.deref_mut())
            .await?)
    }

    /// The user signed in on a device becomes its owner, if the device with this ID was
    /// registered with this uuid. The group stays. False if no such device is registered.
    pub async fn set_owner_from_login(&self, id: &str, uuid: &[u8], owner: &str) -> ResultType<bool> {
        let done = sqlx::query(
            "insert into device_owner(guid, owner) select guid, ? from peer where id = ? and uuid = ?
             on conflict(guid) do update set owner = excluded.owner",
        )
        .bind(owner)
        .bind(id)
        .bind(uuid)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(done.rows_affected() > 0)
    }
}

/// An address book.
#[derive(Clone, Debug, PartialEq)]
pub struct AbRow {
    pub guid: String,
    pub owner: String,
    pub name: String,
    pub personal: bool,
}

/// A user of the panel list.
pub struct UserRow {
    pub name: String,
    /// UTC, '' if never noted.
    pub last_login: String,
    pub blocked: bool,
    /// Last use of a client token or panel session, UTC, '' if never noted.
    pub last_active: String,
}

/// A token for setting up devices (see deploy_token).
pub struct DeployTokenRow {
    pub id: i64,
    pub created_by: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub note: String,
    pub uses: i64,
}

/// A registered device with its owner and group ('' for none).
pub struct DeviceRow {
    pub id: String,
    pub info: String,
    pub registered: String,
    pub owner: String,
    pub group: String,
    /// The ID an admin gave the device, None if none yet.
    pub assigned_id: Option<String>,
    /// The device's last system info as JSON, '' if it sent none.
    pub sysinfo: String,
    /// When the device was last seen (unix seconds) as the database knows it, 0 if never.
    pub last_seen: u64,
}

/// A new row of the log (see audit_log).
#[derive(Default)]
pub struct NewAudit {
    pub created_at: u64,
    pub kind: &'static str,
    pub device_guid: Option<Vec<u8>>,
    pub device_id: String,
    pub user: String,
    pub peer_id: String,
    pub peer_name: String,
    pub ip: String,
    pub conn_id: i64,
    pub authorized: bool,
    pub detail: String,
}

/// A row of the log as the page "Protokoll" shows it.
pub struct AuditRow {
    pub created_at: u64,
    pub kind: String,
    pub device_id: String,
    pub user: String,
    pub peer_id: String,
    pub peer_name: String,
    pub ip: String,
    pub authorized: bool,
    pub ended_at: Option<u64>,
    pub detail: String,
}

/// Which rows of the log to show. Text filters match a part, in any case.
#[derive(Default)]
pub struct AuditFilter {
    /// Only what this Benutzer may see; None for an admin.
    pub visible_to: Option<String>,
    pub device: String,
    pub user: String,
    /// From this time on and before `until` (unix seconds).
    pub from: Option<u64>,
    pub until: Option<u64>,
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
