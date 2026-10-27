//! The wall clock as the node records it: Unix seconds.

use std::time::UNIX_EPOCH;

#[inline(always)]
pub fn current_time_secs() -> i64 {
    std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
