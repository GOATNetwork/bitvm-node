//! The committee instance keys on disk and this node's membership of an instance.

use crate::env::*;
use anyhow::{Context, Result};
use bitcoin::PublicKey;
use bitcoin::key::Keypair;
use bitvm_lib::keys::CommitteeMasterKey;
use client::goat_chain::GOATClient;
use std::path::PathBuf;

use uuid::Uuid;

/// Path of the committee instance key envelope for `instance_id`.
pub fn committee_instance_keys_envelope_path(instance_id: Uuid) -> PathBuf {
    let mut envelope_path = PathBuf::from(COMMITTEE_INSTANCE_KEYS_DIR);
    envelope_path.push(format!("{instance_id}.json"));
    envelope_path
}

/// Whether this node signs for an instance: it holds the instance key
/// envelope and that key is in the instance's committee on Goat. Nodes that
/// did not answer the peg-in request hold no envelope and take no part in
/// the instance's signing rounds.
pub enum CommitteeMembership {
    Member(bitcoin::key::Keypair),
    NotMember(String),
}

pub async fn local_committee_membership(
    goat_client: &GOATClient,
    instance_id: Uuid,
) -> Result<CommitteeMembership> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    if !envelope_path.exists() {
        return Ok(CommitteeMembership::NotMember("no instance key envelope".to_string()));
    }
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let keypair = match load_committee_instance_keypair(&committee_master_key, instance_id) {
        Ok(keypair) => keypair,
        Err(error) if is_io_not_found_error(&error) => {
            return Ok(CommitteeMembership::NotMember(
                "instance key envelope vanished".to_string(),
            ));
        }
        Err(error) => return Err(error),
    };
    let pubkey: PublicKey = keypair.public_key().into();
    let committee = goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    if !committee.contains(&pubkey) {
        return Ok(CommitteeMembership::NotMember(format!(
            "instance key {pubkey} is not in the committee on Goat"
        )));
    }
    Ok(CommitteeMembership::Member(keypair))
}

pub fn is_io_not_found_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
    })
}

pub(crate) fn load_committee_instance_keypair(
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(|| {
        format!(
            "load committee instance keypair failed for {} at {}",
            instance_id,
            envelope_path.display()
        )
    })
}
