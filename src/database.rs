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
        ] {
            sqlx::query(statement)
                .execute(self.pool.get().await?.deref_mut())
                .await?;
        }
        self.add_column("api_token", "last_used", "datetime").await?;
        self.add_column("panel_user", "last_login", "datetime").await?;
        self.add_column("panel_user", "blocked", "integer not null default 0").await?;
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

    /// All registered devices with owner and group, sorted by id.
    pub async fn list_devices(&self) -> ResultType<Vec<DeviceRow>> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
            "select p.id, p.info, cast(p.created_at as text), coalesce(o.owner, ''), coalesce(o.grp, '')
             from peer p left join device_owner o on o.guid = p.guid
             order by p.id collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, info, registered, owner, group)| DeviceRow {
                id,
                info,
                registered,
                owner,
                group,
            })
            .collect())
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

/// A registered device with its owner and group ('' for none).
pub struct DeviceRow {
    pub id: String,
    pub info: String,
    pub registered: String,
    pub owner: String,
    pub group: String,
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
