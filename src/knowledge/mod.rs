use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::is_valid_slug;
use crate::identity::orgs::{record, require_member};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid, text, unique_violation};
use crate::platform::events::{self, Cause};
use crate::platform::page::Page;

const MAX_BODY_CHARS: usize = 200_000;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Article {
    pub id: Uuid,
    pub category_id: Option<Uuid>,
    pub title: String,
    pub slug: String,
    pub body: String,
    pub visibility: String,
    pub state: String,
    pub author_id: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub published_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! article_columns {
    () => {
        "id, category_id, title, slug, body, visibility, state, author_id, updated_by, published_at, created_at, updated_at"
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reader {
    Editor,
    Internal,
    Public,
}

async fn reader(conn: &mut PgConnection, org_id: Uuid, actor: Actor) -> ServiceResult<Reader> {
    require_member(conn, org_id, actor).await?;
    let missing = authz::missing_permissions(
        conn,
        org_id,
        None,
        actor,
        [Permission::KnowledgeEdit, Permission::KnowledgeReadPrivate],
    )
    .await?;
    Ok(if !missing.contains(&Permission::KnowledgeEdit) {
        Reader::Editor
    } else if !missing.contains(&Permission::KnowledgeReadPrivate) {
        Reader::Internal
    } else {
        Reader::Public
    })
}

pub async fn list_categories(conn: &mut PgConnection, org_id: Uuid, actor: Actor) -> ServiceResult<Vec<Category>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as("SELECT id, name, position, created_at FROM kb_categories WHERE org_id = $1 ORDER BY position, name")
        .bind(org_id)
        .fetch_all(conn)
        .await?)
}

pub async fn save_category(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    name: &str,
    position: i32,
) -> ServiceResult<Category> {
    let name = text("name", name, 100)?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgeEdit).await?;
    let id = existing.unwrap_or_else(Uuid::now_v7);
    let result = if existing.is_some() {
        sqlx::query_as(
            "UPDATE kb_categories SET name = $3, position = $4 WHERE org_id = $1 AND id = $2
             RETURNING id, name, position, created_at",
        )
        .bind(org_id)
        .bind(id)
        .bind(&name)
        .bind(position)
        .fetch_optional(&mut *tx)
        .await
    } else {
        sqlx::query_as(
            "INSERT INTO kb_categories (id, org_id, name, position) VALUES ($1, $2, $3, $4)
             RETURNING id, name, position, created_at",
        )
        .bind(id)
        .bind(org_id)
        .bind(&name)
        .bind(position)
        .fetch_optional(&mut *tx)
        .await
    };
    let category: Category = result
        .map_err(|err| {
            if unique_violation(&err, "kb_categories_name_key") {
                conflict("name_taken", "a category with this name already exists")
            } else {
                err.into()
            }
        })?
        .ok_or(ServiceError::NotFound)?;
    record(&mut tx, org_id, actor, "kb_category.saved", "kb_category", id, json!({ "name": name })).await?;
    tx.commit().await?;
    Ok(category)
}

pub async fn delete_category(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgeEdit).await?;
    let deleted = sqlx::query("DELETE FROM kb_categories WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, "kb_category.deleted", "kb_category", id, json!({})).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ArticleFilter {
    pub q: Option<String>,
    pub state: Option<String>,
    pub visibility: Option<String>,
    pub category_id: Option<Uuid>,
}

pub async fn list_articles(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    filter: &ArticleFilter,
    page: Page,
) -> ServiceResult<Vec<Article>> {
    let reader = reader(conn, org_id, actor).await?;
    let q = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        article_columns!(),
        " FROM kb_articles
         WHERE org_id = $1
           AND ($2 OR state = 'published')
           AND ($3 OR visibility = 'public')
           AND ($4::text IS NULL OR state = $4)
           AND ($5::text IS NULL OR visibility = $5)
           AND ($6::uuid IS NULL OR category_id = $6)
           AND ($7::text IS NULL OR search_vector @@ websearch_to_tsquery('simple', $7))
           AND ($8::uuid IS NULL OR id < $8)
         ORDER BY id DESC LIMIT $9"
    ))
    .bind(org_id)
    .bind(reader == Reader::Editor)
    .bind(reader != Reader::Public)
    .bind(filter.state.as_deref())
    .bind(filter.visibility.as_deref())
    .bind(filter.category_id)
    .bind(q)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub async fn get_article(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<Article> {
    let reader = reader(conn, org_id, actor).await?;
    let article = load(conn, org_id, id).await?;
    let visible = match reader {
        Reader::Editor => true,
        Reader::Internal => article.state == "published",
        Reader::Public => article.state == "published" && article.visibility == "public",
    };
    if visible { Ok(article) } else { Err(ServiceError::NotFound) }
}

async fn load(conn: &mut PgConnection, org_id: Uuid, id: Uuid) -> ServiceResult<Article> {
    sqlx::query_as(concat!("SELECT ", article_columns!(), " FROM kb_articles WHERE org_id = $1 AND id = $2"))
        .bind(org_id)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(ServiceError::NotFound)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ArticleInput {
    pub title: Option<String>,
    pub slug: Option<String>,
    pub body: Option<String>,
    pub visibility: Option<String>,
    #[serde(default, deserialize_with = "double")]
    pub category_id: Option<Option<Uuid>>,
}

fn double<'de, D>(deserializer: D) -> Result<Option<Option<Uuid>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Uuid>::deserialize(deserializer).map(Some)
}

fn slugify(title: &str) -> String {
    let mut slug = String::new();
    for c in title.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug: String = slug.trim_end_matches('-').chars().take(100).collect();
    let slug = slug.trim_end_matches('-').to_string();
    if slug.is_empty() { "article".into() } else { slug }
}

fn check_visibility(value: &str) -> ServiceResult<()> {
    if matches!(value, "public" | "internal") {
        Ok(())
    } else {
        Err(invalid("visibility", "must be public or internal"))
    }
}

fn check_body(body: &str) -> ServiceResult<()> {
    if body.chars().count() > MAX_BODY_CHARS {
        Err(invalid("body", "is too long"))
    } else {
        Ok(())
    }
}

fn check_slug(slug: &str) -> ServiceResult<()> {
    if is_valid_slug(slug) {
        Ok(())
    } else {
        Err(invalid("slug", "must be lowercase letters, digits, and hyphens"))
    }
}

pub async fn create_article(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    input: ArticleInput,
) -> ServiceResult<Article> {
    let title = text("title", input.title.as_deref().unwrap_or_default(), 300)?;
    let body = input.body.unwrap_or_default();
    check_body(&body)?;
    let visibility = input.visibility.unwrap_or_else(|| "internal".into());
    check_visibility(&visibility)?;
    let mut slug = input.slug.unwrap_or_else(|| slugify(&title));
    check_slug(&slug)?;

    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgeEdit).await?;
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kb_articles WHERE org_id = $1 AND slug = $2)")
        .bind(org_id)
        .bind(&slug)
        .fetch_one(&mut *tx)
        .await?;
    let id = Uuid::now_v7();
    if taken {
        let suffix = id.simple().to_string();
        slug = format!("{}-{}", slug.chars().take(100).collect::<String>(), &suffix[suffix.len() - 6..]);
    }
    let author = match actor {
        Actor::User(id) => Some(id),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO kb_articles (id, org_id, category_id, title, slug, body, visibility, author_id, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
    )
    .bind(id)
    .bind(org_id)
    .bind(input.category_id.flatten())
    .bind(&title)
    .bind(&slug)
    .bind(&body)
    .bind(&visibility)
    .bind(author)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
            invalid("category_id", "is not a category in this organization")
        } else {
            err.into()
        }
    })?;
    record(&mut tx, org_id, actor, "article.created", "article", id, json!({ "title": title })).await?;
    let article = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(article)
}

pub async fn update_article(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    input: ArticleInput,
) -> ServiceResult<Article> {
    let title = input.title.as_deref().map(|t| text("title", t, 300)).transpose()?;
    if let Some(body) = &input.body {
        check_body(body)?;
    }
    if let Some(visibility) = &input.visibility {
        check_visibility(visibility)?;
    }
    if let Some(slug) = &input.slug {
        check_slug(slug)?;
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgeEdit).await?;
    let current = load(&mut tx, org_id, id).await?;
    if input.visibility.as_deref() == Some("public") && current.visibility != "public" && current.state == "published" {
        authz::require(&mut tx, org_id, actor, Permission::KnowledgePublish).await?;
    }
    let editor = match actor {
        Actor::User(id) => Some(id),
        _ => None,
    };
    sqlx::query(
        "UPDATE kb_articles SET title = coalesce($3, title), slug = coalesce($4, slug), body = coalesce($5, body),
             visibility = coalesce($6, visibility),
             category_id = CASE WHEN $7 THEN $8 ELSE category_id END,
             updated_by = coalesce($9, updated_by)
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(&title)
    .bind(&input.slug)
    .bind(&input.body)
    .bind(&input.visibility)
    .bind(input.category_id.is_some())
    .bind(input.category_id.flatten())
    .bind(editor)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if unique_violation(&err, "kb_articles_org_id_slug_key") {
            conflict("slug_taken", "another article uses this slug")
        } else if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
            invalid("category_id", "is not a category in this organization")
        } else {
            err.into()
        }
    })?;
    record(&mut tx, org_id, actor, "article.updated", "article", id, json!({ "title": title })).await?;
    let article = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(article)
}

pub async fn set_state(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid, state: &str) -> ServiceResult<Article> {
    if !matches!(state, "draft" | "published" | "archived") {
        return Err(invalid("state", "must be draft, published, or archived"));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgePublish).await?;
    let updated = sqlx::query(
        "UPDATE kb_articles SET state = $3,
             published_at = CASE WHEN $3 = 'published' THEN coalesce(published_at, now()) ELSE published_at END
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(state)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, &format!("article.{state}"), "article", id, json!({})).await?;
    if state == "published" {
        events::emit(&mut tx, org_id, "article.published", "article", id, json!({ "article_id": id }), Cause::default())
            .await?;
    }
    let article = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(article)
}

pub async fn delete_article(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::KnowledgeDelete).await?;
    let deleted = sqlx::query("DELETE FROM kb_articles WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, "article.deleted", "article", id, json!({})).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PublicArticle {
    pub id: Uuid,
    pub category_id: Option<Uuid>,
    pub title: String,
    pub slug: String,
    pub body: String,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

pub async fn help_center(
    conn: &mut PgConnection,
    org_slug: &str,
    q: Option<&str>,
    page: Page,
) -> ServiceResult<Vec<PublicArticle>> {
    let q = q.map(str::trim).filter(|q| !q.is_empty());
    Ok(sqlx::query_as(
        "SELECT a.id, a.category_id, a.title, a.slug, a.body, a.published_at, a.updated_at
         FROM kb_articles a JOIN organizations o ON o.id = a.org_id AND o.deleted_at IS NULL
         WHERE o.slug = $1 AND a.state = 'published' AND a.visibility = 'public'
           AND ($2::text IS NULL OR a.search_vector @@ websearch_to_tsquery('simple', $2))
           AND ($3::uuid IS NULL OR a.id < $3)
         ORDER BY a.id DESC LIMIT $4",
    )
    .bind(org_slug)
    .bind(q)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub async fn help_article(conn: &mut PgConnection, org_slug: &str, slug: &str) -> ServiceResult<PublicArticle> {
    sqlx::query_as(
        "SELECT a.id, a.category_id, a.title, a.slug, a.body, a.published_at, a.updated_at
         FROM kb_articles a JOIN organizations o ON o.id = a.org_id AND o.deleted_at IS NULL
         WHERE o.slug = $1 AND a.slug = $2 AND a.state = 'published' AND a.visibility = 'public'",
    )
    .bind(org_slug)
    .bind(slug)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::slugify;

    #[test]
    fn slugs_come_from_titles() {
        assert_eq!(slugify("Reset your VPN password!"), "reset-your-vpn-password");
        assert_eq!(slugify("¿¿??"), "article");
    }
}
