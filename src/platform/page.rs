use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::platform::error::{ServiceResult, invalid};

#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub cursor: Option<Uuid>,
}

#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub limit: i64,
    pub cursor: Option<Uuid>,
}

impl PageQuery {
    pub fn page(self) -> ServiceResult<Page> {
        let limit = self.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(invalid("limit", "must be between 1 and 100"));
        }
        Ok(Page {
            limit,
            cursor: self.cursor,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Paged<T> {
    pub data: Vec<T>,
    pub next_cursor: Option<Uuid>,
}

impl<T> Paged<T> {
    pub fn new(mut rows: Vec<T>, page: Page, id: impl Fn(&T) -> Uuid) -> Self {
        let next_cursor = if rows.len() as i64 > page.limit {
            rows.truncate(page.limit as usize);
            rows.last().map(&id)
        } else {
            None
        };
        Self {
            data: rows,
            next_cursor,
        }
    }
}
