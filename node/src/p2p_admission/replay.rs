//! Replay protection: one sequence window per author, with a lockout for
//! authors that keep sending stale or far-future messages.

use anyhow::Result;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use super::DropReason;

/// Number of sequence positions retained below the high-water mark.
pub(super) const REPLAY_WINDOW: u64 = 1_024;
const REPLAY_MAX_TRACKED_AUTHORS: usize = 16_384;

/// Maximum accepted sequence-number lead over local wall time.
pub(super) const REPLAY_MAX_FUTURE: Duration = Duration::from_secs(10 * 60);
/// Below-floor rejections of one author per tick that are worth an operator's
/// attention; see [`ReplayGuard::take_lockout_suspects`].
pub(super) const REPLAY_LOCKOUT_SUSPECT_REJECTIONS: u32 = 8;

#[derive(Debug, Default)]
struct AuthorSequence {
    highest: u64,
    /// Sequence numbers seen within `REPLAY_WINDOW` of `highest`.
    recent: std::collections::BTreeSet<u64>,
    /// Rejection count since the last report; diagnostic only.
    rejected: u32,
}

/// Per-registered-author sequence window, in memory only: accept unseen numbers
/// within `REPLAY_WINDOW` of the highest one admitted. A restart re-opens every
/// window; what a replay can then re-inject is bounded by the engine inbox's
/// content-id dedup and, for a registered author, charged to its own rate budget.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    authors: Mutex<HashMap<PeerId, AuthorSequence>>,
    /// How far each registered author's numbering ran ahead of the local clock
    /// since the last report; see [`Self::take_clock_leads`].
    clock_leads: Mutex<HashMap<PeerId, u64>>,
}

/// Authors remembered per tick for the clock report. It is a diagnostic, and the
/// table must stay small whatever arrives.
const CLOCK_LEADS_MAX_AUTHORS: usize = 64;

impl ReplayGuard {
    /// Record `sequence_number` for `author`, or refuse it. `unix_nanos` is the
    /// local wall clock.
    pub fn admit(
        &self,
        author: &PeerId,
        sequence_number: Option<u64>,
        unix_nanos: u64,
    ) -> Result<(), DropReason> {
        // Require a signed sequence number.
        let sequence_number = sequence_number.ok_or(DropReason::ReplayedSequence)?;
        if sequence_number > unix_nanos {
            self.note_clock_lead(author, sequence_number - unix_nanos);
        }
        if sequence_number > unix_nanos.saturating_add(REPLAY_MAX_FUTURE.as_nanos() as u64) {
            return Err(DropReason::FutureSequence);
        }
        let mut authors = self.authors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !authors.contains_key(author) && authors.len() >= REPLAY_MAX_TRACKED_AUTHORS {
            // Only reachable if the registries outgrow the table; forgetting an
            // author merely re-opens its window once.
            if let Some(evicted) = authors.keys().next().copied() {
                authors.remove(&evicted);
            }
        }
        let state = authors.entry(*author).or_default();
        if sequence_number > state.highest {
            state.highest = sequence_number;
            let floor = sequence_number.saturating_sub(REPLAY_WINDOW);
            state.recent = state.recent.split_off(&floor);
        } else if state.highest - sequence_number >= REPLAY_WINDOW
            || state.recent.contains(&sequence_number)
        {
            state.rejected = state.rejected.saturating_add(1);
            return Err(DropReason::ReplayedSequence);
        }
        state.recent.insert(sequence_number);
        Ok(())
    }

    fn note_clock_lead(&self, author: &PeerId, lead_nanos: u64) {
        let mut leads = self.clock_leads.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if leads.len() < CLOCK_LEADS_MAX_AUTHORS || leads.contains_key(author) {
            let lead = leads.entry(*author).or_default();
            *lead = (*lead).max(lead_nanos);
        }
    }

    /// Return and clear each registered author's maximum clock lead since the previous call.
    pub fn take_clock_leads(&self) -> Vec<(PeerId, Duration)> {
        let mut leads = self.clock_leads.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        leads.drain().map(|(author, lead)| (author, Duration::from_nanos(lead))).collect()
    }

    /// Return authors exceeding the rejection reporting threshold.
    pub fn take_lockout_suspects(&self) -> Vec<(PeerId, u32)> {
        let mut authors = self.authors.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        authors
            .iter_mut()
            .filter_map(|(author, state)| {
                let rejected = std::mem::take(&mut state.rejected);
                (rejected >= REPLAY_LOCKOUT_SUSPECT_REJECTIONS).then_some((*author, rejected))
            })
            .collect()
    }
}

/// The local wall clock in the unit gossipsub numbers its messages in.
pub fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos().min(u128::from(u64::MAX)) as u64)
}

pub fn replay_guard() -> &'static ReplayGuard {
    &REPLAY_GUARD
}

static REPLAY_GUARD: LazyLock<ReplayGuard> = LazyLock::new(ReplayGuard::default);
