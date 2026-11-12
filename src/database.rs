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
        ] {
            sqlx::query(statement)
                .execute(self.pool.get().await?.deref_mut())
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

    /// The user of a token, if the token exists and its user still exists.
    pub async fn get_api_token_user(&self, token_hash: &str) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>(
            "select t.user from api_token t join panel_user u on u.name = t.user where t.token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn delete_api_token(&self, token_hash: &str) -> ResultType<()> {
        sqlx::query("delete from api_token where token_hash = ?")
            .bind(token_hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
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

    pub async fn ab_owner(&self, guid: &str) -> ResultType<Option<String>> {
        Ok(sqlx::query_scalar::<_, String>("select owner from ab where guid = ?")
            .bind(guid)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?)
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

    pub async fn count_panel_users(&self) -> ResultType<i64> {
        Ok(
            sqlx::query_scalar::<_, i64>("select count(*) from panel_user")
                .fetch_one(self.pool.get().await?.deref_mut())
                .await?,
        )
    }

    pub async fn insert_panel_user(&self, name: &str, password_hash: &str) -> ResultType<()> {
        sqlx::query("insert into panel_user(name, password_hash) values(?, ?)")
            .bind(name)
            .bind(password_hash)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn get_panel_password_hash(&self, name: &str) -> ResultType<Option<String>> {
        Ok(
            sqlx::query_scalar::<_, String>("select password_hash from panel_user where name = ?")
                .bind(name)
                .fetch_optional(self.pool.get().await?.deref_mut())
                .await?,
        )
    }

    /// All registered devices as (id, info json, registered at), sorted by id.
    pub async fn list_peers(&self) -> ResultType<Vec<(String, String, String)>> {
        Ok(sqlx::query_as::<_, (String, String, String)>(
            "select id, info, cast(created_at as text) from peer order by id collate nocase",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }
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
