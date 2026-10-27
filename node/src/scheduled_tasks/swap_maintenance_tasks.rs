//! Swap escrow maintenance: escrows whose refund deadline has passed are
//! marked timed out.

use crate::clock::current_time_secs;
use store::localdb::LocalDB;
use tracing::info;

/// Mark still-initializing swap escrows whose refund deadline has passed as
/// timed out.
pub async fn swap_escrow_timeout_monitor(local_db: &LocalDB) -> anyhow::Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let timed_out = storage_processor.timeout_expired_swap_escrows(current_time_secs()).await?;
    if timed_out > 0 {
        info!("marked {timed_out} swap escrows as timed out");
    }
    Ok(())
}
