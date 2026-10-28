



#![allow(dead_code)]

pub mod app;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sqlx::PgPool;
use ultrivly::identity::{self, CreatedOrganization, NewOrganization};
use uuid::Uuid;

pub async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, 'Someone')")
        .bind(id)
        .bind(format!("{id}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    id
}



pub async fn create_org(pool: &PgPool, slug: &'static str) -> (CreatedOrganization, Uuid) {
    let owner = create_user(pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let org = identity::create_organization(
        &mut conn,
        NewOrganization {
            name: "Org",
            slug,
            workspace_name: "Support",
            workspace_slug: "support",
            owner_user_id: owner,
        },
    )
    .await
    .unwrap();
    (org, owner)
}

pub async fn create_workspace(pool: &PgPool, org_id: Uuid, slug: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $3)")
        .bind(id)
        .bind(org_id)
        .bind(slug)
        .execute(pool)
        .await
        .unwrap();
    id
}


pub async fn add_member(pool: &PgPool, org_id: Uuid) -> (Uuid, Uuid) {
    let user = create_user(pool).await;
    let membership = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(membership)
    .bind(org_id)
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
    (user, membership)
}


pub async fn grant(
    pool: &PgPool,
    org_id: Uuid,
    membership_id: Uuid,
    role_id: Uuid,
    workspace_id: Option<Uuid>,
) {
    sqlx::query(
        "INSERT INTO membership_roles (org_id, membership_id, role_id, workspace_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(membership_id)
    .bind(role_id)
    .bind(workspace_id)
    .execute(pool)
    .await
    .unwrap();
}


pub async fn member_with_role(
    pool: &PgPool,
    org_id: Uuid,
    role_id: Uuid,
    workspace_id: Option<Uuid>,
) -> Uuid {
    let (user, membership) = add_member(pool, org_id).await;
    grant(pool, org_id, membership, role_id, workspace_id).await;
    user
}

pub async fn role_id(pool: &PgPool, org_id: Uuid, key: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM roles WHERE org_id = $1 AND key = $2")
        .bind(org_id)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

pub async fn membership_id(pool: &PgPool, org_id: Uuid, user_id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM memberships WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}


pub fn totp(secret_base32: &str, time: u64) -> String {
    let mut bits = 0u64;
    let mut nbits = 0;
    let mut seed = Vec::new();
    for c in secret_base32.chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).unwrap() as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            seed.push((bits >> (nbits - 8)) as u8);
            nbits -= 8;
        }
    }
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(&seed).unwrap();
    mac.update(&(time / 30).to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let o = (hash[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([hash[o], hash[o + 1], hash[o + 2], hash[o + 3]]) & 0x7fff_ffff;
    format!("{:06}", n % 1_000_000)
}
