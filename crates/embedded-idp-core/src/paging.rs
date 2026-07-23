use std::time::SystemTime;

pub const DEFAULT_PAGE_LIMIT: u32 = 50;
pub const MAX_PAGE_LIMIT: u32 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub limit: u32,
    pub offset: u64,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            offset: 0,
        }
    }
}

impl PageRequest {
    pub fn fetch_limit(&self) -> i64 {
        i64::from(self.limit) + 1
    }

    pub fn sql_offset(&self) -> i64 {
        self.offset.min(i64::MAX as u64) as i64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMetadata {
    pub limit: u32,
    pub offset: u64,
    pub returned: u32,
    pub total: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimePageCursor {
    pub sort_time: SystemTime,
    pub entity_id: String,
}

pub(crate) fn finalize_page<T>(
    mut items: Vec<T>,
    page: PageRequest,
    total: u64,
) -> (Vec<T>, PageMetadata) {
    let has_more = items.len() > page.limit as usize;
    if has_more {
        items.truncate(page.limit as usize);
    }

    let returned = items.len() as u32;
    (
        items,
        PageMetadata {
            limit: page.limit,
            offset: page.offset,
            returned,
            total,
            has_more,
        },
    )
}
