use crate::PublicKeyCache;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub static PUBLIC_KEY_CACHE: Lazy<Mutex<PublicKeyCache>> =
    Lazy::new(|| Mutex::new(PublicKeyCache::new()));
