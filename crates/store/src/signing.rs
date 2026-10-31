//! Bind each signing nonce to one transcript before producing its signature.

use crate::localdb::StorageProcessor;
use sqlx::Row;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningAuthorization {
    /// First authorization of this nonce for this transcript.
    Authorized,
    /// The same nonce was already authorized for the same transcript; a retry
    /// may sign it again.
    Repeated,
    /// The nonce is bound to another transcript: never sign.
    Conflict { existing_digest: String },
}

impl<'a> StorageProcessor<'a> {
    /// Authorize `nonce_id` for `transcript_digest` under `scope_kind:scope_id`.
    pub async fn authorize_signing(
        &mut self,
        scope_kind: &str,
        scope_id: &str,
        nonce_id: &str,
        transcript_digest: &str,
        now: i64,
    ) -> anyhow::Result<SigningAuthorization> {
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO signing_authorization \
             (nonce_id, scope_kind, scope_id, transcript_digest, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(nonce_id)
        .bind(scope_kind)
        .bind(scope_id)
        .bind(transcript_digest)
        .bind(now)
        .execute(self.conn())
        .await?
        .rows_affected()
            > 0;
        if inserted {
            return Ok(SigningAuthorization::Authorized);
        }
        let existing: String =
            sqlx::query("SELECT transcript_digest FROM signing_authorization WHERE nonce_id = ?")
                .bind(nonce_id)
                .fetch_one(self.conn())
                .await?
                .try_get("transcript_digest")?;
        if existing == transcript_digest {
            Ok(SigningAuthorization::Repeated)
        } else {
            Ok(SigningAuthorization::Conflict { existing_digest: existing })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localdb::create_local_db;

    #[tokio::test]
    async fn a_nonce_binds_to_one_transcript() {
        let db = create_local_db("sqlite::memory:").await;
        let mut storage = db.acquire().await.unwrap();
        assert_eq!(
            storage.authorize_signing("graph", "g1", "n1", "t1", 1).await.unwrap(),
            SigningAuthorization::Authorized
        );
        assert_eq!(
            storage.authorize_signing("graph", "g1", "n1", "t1", 2).await.unwrap(),
            SigningAuthorization::Repeated
        );
        let conflict = storage.authorize_signing("graph", "g1", "n1", "t2", 3).await.unwrap();
        assert_eq!(conflict, SigningAuthorization::Conflict { existing_digest: "t1".into() });
    }
}
