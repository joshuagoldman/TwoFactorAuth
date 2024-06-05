use std::collections::HashMap;

use parse_duration::parse;
use std::hash::Hash;
use std::io::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::models::SessionInfo;

pub fn token_has_not_expired(
    token_created_time: &std::time::SystemTime,
    session_duration_str: &String,
) -> bool {
    let max_duration = parse(session_duration_str).unwrap_or(std::time::Duration::new(3600, 0));

    let elapsed_time = token_created_time.elapsed().unwrap();

    if elapsed_time.as_secs() > max_duration.as_secs() {
        false
    } else {
        true
    }
}

pub type AppCache<T> = Arc<Mutex<Cache<T>>>;

pub struct CacheReturn<T, U> {
    pub key: T,
    pub value: U,
}

pub struct Cache<T> {
    items: HashMap<T, SessionInfo>,
    time_limit: String,
    pub life_time_guid: uuid::Uuid,
}

impl<T: std::cmp::Eq + PartialEq + Hash + Clone + std::fmt::Display> Cache<T> {
    pub fn new(time_limit: String) -> Cache<T> {
        Cache {
            time_limit,
            items: HashMap::new(),
            life_time_guid: uuid::Uuid::new_v4(),
        }
    }

    pub fn new_app_cache(time_limit: String) -> AppCache<T> {
        Arc::new(Mutex::new(Cache::new(time_limit)))
    }

    pub fn check(&self, key: T) -> bool {
        let result = self.items.get(&key);

        match result {
            Some(x) => token_has_not_expired(&x.refresh_time, &self.time_limit),
            None => false,
        }
    }

    pub fn remove(&mut self, key: T) {
        if self.items.get(&key).is_some() {
            self.items.remove(&key).unwrap();
        }
    }

    pub fn set(&mut self, key: T, result: SessionInfo) -> Result<(), Error> {
        if self.items.get(&key).is_some() {
            self.items.remove(&key).unwrap();
        }

        self.items.insert(key.clone(), result.clone());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::middleware::{
        cache,
        models::{SessionInfo, SessionType},
    };

    #[tokio::test]
    async fn test_cache_logged_in_within_time() {
        let app_cache: std::sync::Arc<tokio::sync::Mutex<cache::Cache<uuid::Uuid>>> =
            cache::Cache::new_app_cache("3 seconds".to_string());

        let mut local_cache = app_cache.lock().await;

        let id = uuid::Uuid::new_v4();
        let session_info = SessionInfo {
            user_id: id,
            session_type: SessionType::UserPage.to_string(),
            refresh_time: std::time::SystemTime::now(),
        };

        local_cache.set(id, session_info).unwrap();
        actix::clock::sleep(std::time::Duration::new(1, 0)).await;

        assert_eq!(local_cache.check(id), true);
    }

    #[tokio::test]
    async fn test_cache_not_logged_in_within_time() {
        let app_cache: std::sync::Arc<tokio::sync::Mutex<cache::Cache<uuid::Uuid>>> =
            cache::Cache::new_app_cache("3 seconds".to_string());

        let mut local_cache = app_cache.lock().await;

        let id = uuid::Uuid::new_v4();
        let session_info = SessionInfo {
            id,
            logged_in: false,
            refresh_time: std::time::SystemTime::now(),
        };

        local_cache.set(id, session_info).unwrap();
        actix::clock::sleep(std::time::Duration::new(1, 0)).await;

        assert_eq!(local_cache.check(id), false);
    }

    #[tokio::test]
    async fn test_cache_logged_in_not_within_time() {
        let app_cache: std::sync::Arc<tokio::sync::Mutex<cache::Cache<uuid::Uuid>>> =
            cache::Cache::new_app_cache("2 seconds".to_string());

        let mut local_cache = app_cache.lock().await;

        let id = uuid::Uuid::new_v4();
        let session_info = SessionInfo {
            id,
            logged_in: true,
            refresh_time: std::time::SystemTime::now(),
        };

        local_cache.set(id, session_info).unwrap();
        actix::clock::sleep(std::time::Duration::new(3, 0)).await;

        assert_eq!(local_cache.check(id), false);
    }
}
