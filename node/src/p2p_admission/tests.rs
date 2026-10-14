use super::rate::RATE_BUCKET_IDLE_FORGET;
use super::registry::{
    COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE, COMMITTEE_MAX_IN_FLIGHT_LOOKUPS,
    COMMITTEE_MAX_UNKNOWN_IN_FLIGHT, COMMITTEE_NEGATIVE_TTL, COMMITTEE_POSITIVE_TTL,
    COMMITTEE_STALE_LIMIT, OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE, OPERATOR_STAKE_STALE_LIMIT,
    OPERATOR_STAKE_TTL, REFUSED_PEER_LOOKUPS_PER_MINUTE, VERIFIER_SET_RETRY_INTERVAL,
};
use super::registry_refresh::{REGISTERED_KIND_COMMITTEE, REGISTERED_KIND_OPERATOR};
use super::replay::{REPLAY_LOCKOUT_SUSPECT_REJECTIONS, REPLAY_MAX_FUTURE, REPLAY_WINDOW};
use super::strikes::{STRIKE_BAN, STRIKE_LIMIT, STRIKE_WINDOW};
use super::*;
use crate::messages::{AggNonceConsensus, InitGraph, sign_init_graph};
use bitvm_lib::actors::Actor;
use std::collections::HashSet;
use uuid::Uuid;

const SMALL: InboundLimits = InboundLimits {
    max_json_bytes: 1024,
    max_binary_bytes: 4096,
    global: Quota { rows: 6, bytes: 6000 },
    committee_reserve: Quota { rows: 0, bytes: 0 },
    registered_peer: Quota { rows: 3, bytes: 5000 },
};

fn usage(class: SenderClass, rows: i64, bytes: i64, peer: (i64, i64)) -> InboxClassUsage {
    InboxClassUsage {
        admission_class: class.to_string(),
        rows,
        bytes,
        peer_rows: peer.0,
        peer_bytes: peer.1,
    }
}

/// Use isolated gates in tests.
struct TestGates {
    registry: PeerRegistry,
    replay_guard: ReplayGuard,
    rate_limiter: InboundRateLimiter,
    immediate_limiter: PeerRateLimiter,
    usage_cache: InboxUsageCache,
    local_actor: Actor,
}

/// A wall clock comfortably ahead of every sequence number the tests use.
const WALL_CLOCK: u64 = 1_800_000_000 * 1_000_000_000;

/// A distinct operator key per `index`. The registry never parses it.
fn key(index: u32) -> OperatorKey {
    let mut key = [0x11; 32];
    key[..4].copy_from_slice(&index.to_be_bytes());
    key
}

impl TestGates {
    fn new(immediate_limiter: PeerRateLimiter) -> Self {
        Self {
            local_actor: Actor::Committee,
            registry: PeerRegistry::default(),
            replay_guard: ReplayGuard::default(),
            rate_limiter: InboundRateLimiter::new(RateLimits::defaults()),
            immediate_limiter,
            usage_cache: InboxUsageCache::default(),
        }
    }

    /// Evaluate `data` as authored and relayed by `source`.
    async fn evaluate(
        &self,
        local_db: &LocalDB,
        limits: &InboundLimits,
        source: &PeerId,
        sequence_number: u64,
        data: &[u8],
        now: Instant,
    ) -> InboundVerdict {
        let gates = AdmissionGates {
            registry: &self.registry,
            replay_guard: &self.replay_guard,
            rate_limiter: &self.rate_limiter,
            immediate_limiter: &self.immediate_limiter,
            usage_cache: &self.usage_cache,
            limits,
            local_actor: &self.local_actor,
        };
        let inbound = InboundGossip {
            direct_peer: source,
            source,
            sequence_number: Some(sequence_number),
            data,
        };
        evaluate_inbound_message(local_db, &gates, &inbound, now).await.unwrap()
    }
}

fn test_keypair(seed: u8) -> bitcoin::secp256k1::Keypair {
    bitcoin::secp256k1::Keypair::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
}

/// A committee round value: a durable message a committee node stores.
fn committee_vote() -> GOATMessage {
    let keypair = test_keypair(7);
    let digest = bitcoin::secp256k1::Message::from_digest([3; 32]);
    GOATMessage::new(
        Actor::Committee,
        GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
            instance_id: Uuid::new_v4(),
            graph_id: Uuid::new_v4(),
            committee_pubkey: bitcoin::PublicKey::new(keypair.public_key()),
            consensus_hash: [3; 32],
            signature: bitcoin::secp256k1::Secp256k1::new().sign_schnorr(&digest, &keypair),
        }),
    )
}

/// A durable message a committee node stores (the tests run as Committee).
async fn durable_bytes() -> Vec<u8> {
    committee_vote().serialize_message().await.unwrap()
}

/// An operator's recruitment: kept by verifiers, relayed by everyone else.
fn init_graph() -> GOATMessage {
    let keypair = test_keypair(5);
    let init: InitGraph =
        sign_init_graph(Uuid::new_v4(), Uuid::new_v4(), &keypair, PeerId::random().to_bytes());
    GOATMessage::new(Actor::Verifier, GOATMessageContent::InitGraph(init))
}

#[test]
fn envelope_limits_depend_on_the_encoding_and_the_sender() {
    let json = vec![b'{'; 1025];
    assert_eq!(check_envelope(&json, true, &SMALL), Err(DropReason::OversizedJson));
    assert_eq!(check_envelope(&json[..1024], false, &SMALL), Ok(()));

    let mut binary = b"GOATBIN1".to_vec();
    binary.resize(2048, 0);
    assert_eq!(check_envelope(&binary, false, &SMALL), Err(DropReason::BinaryFromNonVerifier));
    assert_eq!(check_envelope(&binary, true, &SMALL), Ok(()), "above the JSON ceiling");
    binary.resize(4097, 0);
    assert_eq!(check_envelope(&binary, true, &SMALL), Err(DropReason::OversizedBinary));
}

/// Verify GenCircuits fits the binary transport ceiling.
#[tokio::test]
async fn gen_circuits_fits_the_binary_envelope() {
    use crate::messages::GenCircuits;
    use bitvm_lib::babe_adapter::{BABE_N_CC, build_setup_package};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::GenCircuits(GenCircuits {
            instance_id: Uuid::new_v4(),
            graph_id: Uuid::new_v4(),
            verifier_pubkey: bitcoin::PublicKey::new(secret.public_key(&secp)),
            setup_package: build_setup_package(BABE_N_CC).unwrap(),
        }),
    );
    let bytes = message.serialize_message().await.unwrap();
    assert!(GOATMessage::is_binary_envelope(&bytes));
    let limits = InboundLimits::with_inbox_bytes(2 << 20, 2 << 30);
    assert!(bytes.len() > limits.max_json_bytes, "GenCircuits is {} bytes", bytes.len());
    assert!(
        bytes.len() * 5 <= limits.max_binary_bytes * 4,
        "GenCircuits is {} bytes, within 20% of the {} byte ceiling",
        bytes.len(),
        limits.max_binary_bytes
    );
    assert_eq!(check_envelope(&bytes, true, &limits), Ok(()));
    assert!(
        (bytes.len() as i64) * 8 <= limits.registered_peer.bytes,
        "a verifier must be able to have several setups queued"
    );
}

/// Verify graph-bearing JSON fits the configured verifier-slot capacity.
#[test]
fn default_json_ceiling_fits_graphs_with_several_verifier_slots() {
    use bitvm_lib::types::BitvmGcCircuitData;
    use goat::assert_scripts::WireHash;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    // 0xff is the widest byte in JSON's decimal array encoding.
    let slot = BitvmGcCircuitData {
        verifier_pubkey: bitcoin::PublicKey::new(secret.public_key(&secp)),
        final_msg_hashlocks: vec![[0xff; 20]; bitvm_lib::babe_adapter::BABE_M_CC],
        wire_hashes: std::array::from_fn(|_| WireHash {
            true_label_hash: [0xff; 20],
            false_label_hash: [0xff; 20],
        }),
    };
    let slot_len = serde_json::to_vec(&slot).unwrap().len();
    assert!(
        slot_len * 8 <= crate::env::DEFAULT_P2P_MAX_JSON_MESSAGE_BYTES,
        "one GC slot is {slot_len} bytes of JSON"
    );
}

#[test]
fn quota_is_charged_per_sender_and_globally() {
    use SenderClass::{Committee, Registered};

    assert_eq!(check_inbox_quota(Registered, 100, &[], &SMALL), Ok(()));

    // The sender's own rows, in whichever class they were admitted (a
    // committee lookup may complete between two of its messages).
    let own = [usage(Registered, 2, 200, (2, 200)), usage(Committee, 1, 100, (1, 100))];
    assert_eq!(check_inbox_quota(Committee, 100, &own, &SMALL), Err(DropReason::SenderQuota));
    let other = [usage(Registered, 3, 300, (0, 0))];
    assert_eq!(check_inbox_quota(Registered, 100, &other, &SMALL), Ok(()));
    let own_bytes = [usage(Registered, 1, 4950, (1, 4950))];
    assert_eq!(
        check_inbox_quota(Registered, 100, &own_bytes, &SMALL),
        Err(DropReason::SenderQuota)
    );

    // The global ceiling counts every class.
    let full = [usage(Committee, 3, 300, (0, 0)), usage(Registered, 3, 300, (0, 0))];
    assert_eq!(check_inbox_quota(Registered, 100, &full, &SMALL), Err(DropReason::GlobalQuota));
    let heavy = [usage(Registered, 1, 5950, (0, 0))];
    assert_eq!(check_inbox_quota(Registered, 100, &heavy, &SMALL), Err(DropReason::GlobalQuota));
}

#[test]
fn derived_quotas_nest_inside_the_global_ceiling() {
    let limits = InboundLimits::with_inbox_bytes(2 << 20, 2 << 30);
    assert!(limits.registered_peer.bytes < limits.global.bytes);
    assert!(limits.committee_reserve.bytes < limits.global.bytes);
    assert!(limits.registered_peer.rows < limits.global.rows);
    assert!(limits.committee_reserve.rows < limits.global.rows);
    assert!(limits.max_json_bytes as i64 <= limits.registered_peer.bytes);
}

#[test]
fn registry_classifies_from_cache_and_never_blocks() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let (verifier, member, stranger) = (PeerId::random(), PeerId::random(), PeerId::random());

    // Nothing is known yet: everyone is unregistered, and lookups are due.
    assert_eq!(registry.sender_class(&member, now), SenderClass::Unregistered);
    assert_eq!(
        registry.plan_refresh(Some(&member), now),
        RefreshPlan { verifier_set: true, committee_peer: true }
    );
    assert_eq!(
        registry.plan_refresh(Some(&member), now),
        RefreshPlan::default(),
        "a lookup already in flight is not started twice"
    );

    registry.record_verifier_set(Some(vec![verifier.to_bytes()]), now);
    registry.record_committee_peer(&member, Some(true), now);
    assert!(registry.is_verifier(&verifier));
    assert_eq!(registry.sender_class(&verifier, now), SenderClass::Registered);
    assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
    assert!(registry.is_committee(&member, now));
    assert!(!registry.is_committee(&verifier, now), "registered, but not the committee");
    assert_eq!(registry.sender_class(&stranger, now), SenderClass::Unregistered);
    assert_eq!(
        registry.plan_refresh(Some(&verifier), now),
        RefreshPlan::default(),
        "a verifier needs no committee lookup"
    );

    // Past its TTL the member is re-validated but keeps its class meanwhile.
    // The verifier set has aged out by then as well.
    let later = now + COMMITTEE_POSITIVE_TTL;
    assert_eq!(registry.sender_class(&member, later), SenderClass::Committee);
    assert_eq!(
        registry.plan_refresh(Some(&member), later),
        RefreshPlan { verifier_set: true, committee_peer: true }
    );
    registry.record_committee_peer(&member, None, later);
    assert_eq!(
        registry.sender_class(&member, later),
        SenderClass::Committee,
        "a failed lookup leaves the cached answer in place"
    );
    assert_eq!(
        registry.sender_class(&member, now + COMMITTEE_STALE_LIMIT),
        SenderClass::Unregistered,
        "but it is not trusted forever"
    );

    // A failed verifier refresh keeps the previous set and is retried soon,
    // but not on every message.
    registry.record_verifier_set(None, later);
    assert!(registry.is_verifier(&verifier));
    assert!(!registry.plan_refresh(None, later + Duration::from_secs(1)).verifier_set);
    assert!(registry.plan_refresh(None, later + VERIFIER_SET_RETRY_INTERVAL).verifier_set);
}

#[test]
fn unknown_identities_cannot_starve_revalidation_of_known_members() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    registry.record_verifier_set(Some(vec![]), now);
    let member = PeerId::random();
    registry.record_committee_peer(&member, Some(true), now);

    let later = now + COMMITTEE_POSITIVE_TTL;
    let mut started = 0;
    for _ in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
        let stranger = PeerId::random();
        if registry.plan_refresh(Some(&stranger), later).committee_peer {
            started += 1;
            registry.record_committee_peer(&stranger, Some(false), later);
        }
    }
    assert_eq!(started, COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE);
    assert!(
        registry.plan_refresh(Some(&member), later).committee_peer,
        "re-validating a registered peer is not charged to the discovery budget"
    );
}

/// Item 5: even with the unknown-lookup slots saturated and in flight, a
/// known member's re-check must still find a reserved slot.
#[test]
fn known_member_recheck_survives_saturated_unknown_lookups() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    registry.record_verifier_set(Some(vec![]), now);
    let member = PeerId::random();
    registry.record_committee_peer(&member, Some(true), now);

    // Fill and hold the unknown-lookup slots (do not resolve them).
    let mut unknown_in_flight = 0;
    for _ in 0..COMMITTEE_MAX_IN_FLIGHT_LOOKUPS * 2 {
        if registry.plan_refresh(Some(&PeerId::random()), now).committee_peer {
            unknown_in_flight += 1;
        }
    }
    assert_eq!(
        unknown_in_flight, COMMITTEE_MAX_UNKNOWN_IN_FLIGHT,
        "unknown lookups are capped below the total, leaving slots reserved"
    );
    let later = now + COMMITTEE_POSITIVE_TTL;
    assert!(
        registry.plan_refresh(Some(&member), later).committee_peer,
        "a known member re-check uses a reserved slot despite the unknown flood"
    );
}

/// An operator becomes registered only once its proven binding is confirmed
/// to be a staked operator, and a key maps to one peer id at a time.
#[test]
fn operator_binding_grants_registered_only_after_stake_confirmation() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let peer = PeerId::random();
    let pubkey = &key(1);

    registry.observe_operator_binding(&peer, pubkey, 1);
    assert_eq!(
        registry.sender_class(&peer, now),
        SenderClass::Unregistered,
        "a proven binding alone is not enough; stake is unconfirmed"
    );
    assert!(registry.plan_operator_refresh(&peer, pubkey, now));
    assert!(
        !registry.plan_operator_refresh(&peer, pubkey, now),
        "a lookup already in flight is not started twice"
    );
    registry.record_operator_stake(&peer, pubkey, Some(true), now);
    assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);

    // Verify one key registers only one peer.
    let new_peer = PeerId::random();
    registry.observe_operator_binding(&new_peer, pubkey, 2);
    registry.record_operator_stake(&new_peer, pubkey, Some(true), now);
    assert_eq!(registry.sender_class(&new_peer, now), SenderClass::Registered);
    assert_eq!(
        registry.sender_class(&peer, now),
        SenderClass::Unregistered,
        "the superseded peer id loses the class"
    );

    // An older binding for a key already owned by another peer is ignored.
    registry.observe_operator_binding(&peer, pubkey, 1);
    assert_eq!(registry.sender_class(&peer, now), SenderClass::Unregistered);
}

/// The rate budget rejects a flood before decode, charges every tier, and
/// only debits when all tiers pass.
#[test]
fn inbound_rate_budget_bounds_bytes_and_messages_per_tier() {
    const MIB: i64 = 1024 * 1024;
    let limits = RateLimits {
        direct_peer: TierRate {
            msg_burst: 100,
            msg_per_sec: 0,
            byte_burst: 100 * MIB,
            byte_per_sec: 0,
        },
        registered_author: TierRate {
            msg_burst: 100,
            msg_per_sec: 0,
            byte_burst: 100 * MIB,
            byte_per_sec: 0,
        },
        unregistered_author: TierRate {
            msg_burst: 100,
            msg_per_sec: 0,
            byte_burst: 2 * MIB,
            byte_per_sec: 0,
        },
        unregistered_total: TierRate {
            msg_burst: 100,
            msg_per_sec: 0,
            byte_burst: 3 * MIB,
            byte_per_sec: 0,
        },
        unregistered_forward: TierRate {
            msg_burst: 100,
            msg_per_sec: 0,
            byte_burst: 100 * MIB,
            byte_per_sec: 0,
        },
        global: TierRate { msg_burst: 100, msg_per_sec: 0, byte_burst: 100 * MIB, byte_per_sec: 0 },
        committee_reserve: 0.0,
        max_tracked_peers: 16,
    };
    let limiter = InboundRateLimiter::new(limits);
    let now = Instant::now();
    let relay = PeerId::random();
    use SenderClass::{Registered, Unregistered};

    // One unregistered author is capped at its own 2 MiB byte burst.
    let a = PeerId::random();
    assert!(limiter.charge(&relay, &a, Unregistered, MIB, now).is_ok());
    assert_eq!(
        limiter.charge(&relay, &a, Unregistered, 2 * MIB, now),
        Err(DropReason::AuthorRate),
        "the author's own bucket has only 1 MiB left"
    );

    // Verify distinct unregistered authors share the class byte budget.
    let (b, c, d) = (PeerId::random(), PeerId::random(), PeerId::random());
    assert!(limiter.charge(&relay, &b, Unregistered, MIB, now).is_ok());
    assert!(limiter.charge(&relay, &c, Unregistered, MIB, now).is_ok());
    assert_eq!(
        limiter.charge(&relay, &d, Unregistered, MIB, now),
        Err(DropReason::UnregisteredRate)
    );

    // A registered author is not charged against the unregistered pool, and
    // the messages rejected above did not drain the global tier: a fresh
    // registered author is still admitted up to the global burst.
    let op = PeerId::random();
    assert!(limiter.charge(&relay, &op, Registered, 50 * MIB, now).is_ok());
}

#[test]
fn rate_limiter_refills_and_bounds_its_own_memory() {
    let limiter = PeerRateLimiter::new(2.0, 1.0, 2);
    let now = Instant::now();
    let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
    assert!(limiter.allow(&a, now));
    assert!(limiter.allow(&a, now));
    assert!(!limiter.allow(&a, now), "the burst is spent");
    assert!(limiter.allow(&a, now + Duration::from_secs(1)), "one token per second");

    assert!(limiter.allow(&b, now + Duration::from_secs(1)));
    assert!(
        !limiter.allow(&c, now + Duration::from_secs(1)),
        "no room to track a new peer while the tracked ones are active"
    );
    assert!(
        limiter.allow(&c, now + Duration::from_secs(60)),
        "idle peers are forgotten to make room"
    );
}

#[test]
fn response_gate_coalesces_requests_inside_the_cooldown() {
    let gate = ResponseGate::new(Duration::from_secs(10));
    let now = Instant::now();
    assert!(gate.try_respond(now));
    assert!(!gate.take_pending(now + Duration::from_secs(20)), "nothing was deferred");

    assert!(!gate.try_respond(now + Duration::from_secs(1)));
    assert!(!gate.try_respond(now + Duration::from_secs(2)));
    assert!(!gate.take_pending(now + Duration::from_secs(5)), "still cooling down");
    assert!(gate.take_pending(now + Duration::from_secs(10)), "one response for both");
    assert!(!gate.take_pending(now + Duration::from_secs(30)));
    assert!(gate.try_respond(now + Duration::from_secs(30)));
}

#[tokio::test]
async fn verdicts_follow_the_queue_state() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let source = PeerId::random();
    let limits = InboundLimits { registered_peer: Quota { rows: 1, bytes: 4096 }, ..SMALL };

    let verdict = gates.evaluate(&local_db, &limits, &source, 1, b"not a message", now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::Undecodable)));

    // An unregistered author's durable message is relayed, never stored.
    let first = durable_bytes().await;
    let verdict = gates.evaluate(&local_db, &limits, &source, 2, &first, now).await;
    assert!(matches!(verdict, InboundVerdict::Forward));
    let key = key(1);
    gates.registry.observe_operator_binding(&source, &key, 1);
    gates.registry.record_operator_stake(&source, &key, Some(true), now);
    let verdict = gates.evaluate(&local_db, &limits, &source, 3, &first, now).await;
    let InboundVerdict::Enqueue { class, .. } = verdict else {
        panic!("an empty inbox admits the first message of a registered author");
    };
    assert_eq!(class, SenderClass::Registered);
    // What admission recorded: a queued network event of this author.
    let mut storage = local_db.acquire().await.unwrap();
    storage
        .insert_engine_inbox_event(
            &store::NewEngineInboxEvent {
                event_id: "first".to_string(),
                aggregate_kind: "graph".to_string(),
                aggregate_id: "g".to_string(),
                kind: "AggNonceConsensus".to_string(),
                source: "network".to_string(),
                author: source.to_string(),
                admission_class: class.to_string(),
                payload: first.clone(),
                ack: None,
            },
            1,
        )
        .await
        .unwrap();
    drop(storage);

    // Another payload from the same sender is over its row quota, in
    // whichever class it is admitted.
    let second = durable_bytes().await;
    let verdict = gates.evaluate(&local_db, &limits, &source, 4, &second, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::SenderQuota)));
    gates.registry.record_committee_peer(&source, Some(true), now);
    let verdict = gates.evaluate(&local_db, &limits, &source, 5, &second, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::SenderQuota)));
}

/// Verify replay neither passes admission nor consumes rate budget.
#[tokio::test]
async fn replayed_registered_messages_are_dropped_before_the_rate_charge() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let member = PeerId::random();
    gates.registry.record_committee_peer(&member, Some(true), now);

    let message = durable_bytes().await;
    let verdict = gates.evaluate(&local_db, &SMALL, &member, 100, &message, now).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
    for _ in 0..3 {
        let verdict = gates.evaluate(&local_db, &SMALL, &member, 100, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ReplayedSequence)));
    }

    // Unregistered authors use rate limits rather than replay tracking:
    // the same sequence number relayed twice is not a replay to them.
    let stranger = PeerId::random();
    let other = durable_bytes().await;
    for _ in 0..2 {
        let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 7, &other, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward));
    }
}

#[test]
fn replay_window_tolerates_reordering_but_not_reuse() {
    let guard = ReplayGuard::default();
    let author = PeerId::random();
    let base = 1_000_000;
    assert_eq!(guard.admit(&author, Some(base), WALL_CLOCK), Ok(()));
    assert_eq!(guard.admit(&author, Some(base + 5), WALL_CLOCK), Ok(()));
    assert_eq!(guard.admit(&author, Some(base + 3), WALL_CLOCK), Ok(()), "reordered, but new");
    assert_eq!(guard.admit(&author, Some(base + 3), WALL_CLOCK), Err(DropReason::ReplayedSequence));
    assert_eq!(guard.admit(&author, Some(base + 5), WALL_CLOCK), Err(DropReason::ReplayedSequence));
    assert_eq!(guard.admit(&author, None, WALL_CLOCK), Err(DropReason::ReplayedSequence));

    // The author restarts: numbering jumps to the new start-up time, and
    // everything from the previous session falls out of the window.
    let restarted = base + 10 * REPLAY_WINDOW;
    assert_eq!(guard.admit(&author, Some(restarted), WALL_CLOCK), Ok(()));
    assert_eq!(guard.admit(&author, Some(base + 4), WALL_CLOCK), Err(DropReason::ReplayedSequence));
    assert_eq!(guard.admit(&author, Some(restarted - REPLAY_WINDOW + 1), WALL_CLOCK), Ok(()));
    assert_eq!(
        guard.admit(&author, Some(restarted - REPLAY_WINDOW), WALL_CLOCK),
        Err(DropReason::ReplayedSequence)
    );

    // Windows are per author.
    assert_eq!(guard.admit(&PeerId::random(), Some(base), WALL_CLOCK), Ok(()));
}

/// Verify re-announcement preserves stake classification.
#[test]
fn reannounced_operator_binding_keeps_its_stake_verdict() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let peer = PeerId::random();
    let pubkey = &key(1);

    registry.observe_operator_binding(&peer, pubkey, 100);
    assert!(registry.plan_operator_refresh(&peer, pubkey, now));
    assert_eq!(registry.record_operator_stake(&peer, pubkey, Some(true), now), Some(true));
    assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);

    registry.observe_operator_binding(&peer, pubkey, 400);
    assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);
    assert!(
        !registry.plan_operator_refresh(&peer, pubkey, now),
        "the verdict is still fresh, so no lookup is due"
    );

    // Keep the newest binding timestamp.
    let usurper = PeerId::random();
    registry.observe_operator_binding(&usurper, pubkey, 300);
    assert_eq!(registry.sender_class(&peer, now), SenderClass::Registered);
    assert!(!registry.plan_operator_refresh(&usurper, pubkey, now));

    // Every definite verdict is handed back for persisting, changed or not.
    let later = now + OPERATOR_STAKE_TTL;
    assert!(registry.plan_operator_refresh(&peer, pubkey, later));
    assert_eq!(registry.record_operator_stake(&peer, pubkey, Some(true), later), Some(true));
    assert!(registry.plan_operator_refresh(&peer, pubkey, later + OPERATOR_STAKE_TTL));
    assert_eq!(
        registry.record_operator_stake(&peer, pubkey, Some(false), later + OPERATOR_STAKE_TTL),
        Some(false)
    );
}

/// Self-signed operator bindings are free to mint. They may exhaust the
/// operator discovery budget, but not the committee's, and not the
/// re-validation of operators already confirmed.
#[test]
fn operator_binding_flood_spends_only_the_operator_discovery_budget() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    registry.record_verifier_set(Some(vec![]), now);
    let operator = PeerId::random();
    let real = key(0);
    registry.observe_operator_binding(&operator, &real, 1);
    assert!(registry.plan_operator_refresh(&operator, &real, now));
    registry.record_operator_stake(&operator, &real, Some(true), now);

    let mut started = 0;
    for index in 0..(OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
        let (sybil, sybil_key) = (PeerId::random(), key(index + 1));
        registry.observe_operator_binding(&sybil, &sybil_key, 1);
        if registry.plan_operator_refresh(&sybil, &sybil_key, now) {
            started += 1;
            registry.record_operator_stake(&sybil, &sybil_key, Some(false), now);
        }
    }
    // The real operator's own first lookup took one token of the same budget.
    assert_eq!(started + 1, OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE);

    assert!(
        registry.plan_refresh(Some(&PeerId::random()), now).committee_peer,
        "committee discovery has its own budget"
    );
    let due = registry.plan_due_operator_refreshes(now + OPERATOR_STAKE_TTL);
    assert!(
        due.first().is_some_and(|(peer, _)| *peer == operator),
        "the confirmed operator is re-validated first, outside the spent budget"
    );
}

/// Registrations confirmed in an earlier session are trusted at once and are
/// re-validated as known members, not rediscovered through the budget.
#[test]
fn seeded_registrations_are_trusted_and_revalidated_as_known() {
    let registry = PeerRegistry::default();
    // `Instant` cannot be dated before the machine booted; keep clear of it.
    let now = Instant::now() + COMMITTEE_STALE_LIMIT;
    let (member, operator) = (PeerId::random(), PeerId::random());
    registry.seed_verified_committee_peer(&member, now);
    registry.seed_verified_operator(&operator, &key(0), 1, now);
    assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
    assert_eq!(registry.sender_class(&operator, now), SenderClass::Registered);

    // Spend both discovery budgets on strangers.
    registry.record_verifier_set(Some(vec![]), now);
    for index in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
        let stranger = PeerId::random();
        if registry.plan_refresh(Some(&stranger), now).committee_peer {
            registry.record_committee_peer(&stranger, Some(false), now);
        }
        let sybil_key = key(index + 1);
        registry.observe_operator_binding(&stranger, &sybil_key, 1);
        if registry.plan_operator_refresh(&stranger, &sybil_key, now) {
            registry.record_operator_stake(&stranger, &sybil_key, Some(false), now);
        }
    }

    assert_eq!(registry.plan_due_committee_refreshes(now), vec![member]);
    assert!(registry.plan_due_operator_refreshes(now).iter().any(|(peer, _)| *peer == operator));
    // Revoke restored registrations after a negative chain answer.
    assert_eq!(registry.record_committee_peer(&member, Some(false), now), Some(false));
    assert_eq!(registry.sender_class(&member, now), SenderClass::Unregistered);
}

/// A flood of fresh identities must neither grow the bucket table nor evict
/// the peers it already tracks: past the cap they share one bucket.
#[test]
fn rate_table_is_bounded_and_overflow_identities_share_one_bucket() {
    let tier = TierRate { msg_burst: 2, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
    let roomy = TierRate { msg_burst: 1_000, msg_per_sec: 0, byte_burst: 1 << 30, byte_per_sec: 0 };
    let limiter = InboundRateLimiter::new(RateLimits {
        direct_peer: roomy,
        registered_author: roomy,
        unregistered_author: tier,
        unregistered_total: roomy,
        unregistered_forward: roomy,
        global: roomy,
        committee_reserve: 0.0,
        max_tracked_peers: 4,
    });
    let now = Instant::now();
    let relay = PeerId::random();
    use SenderClass::{Registered, Unregistered};

    for _ in 0..4 {
        assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
    }
    // New authors share overflow capacity when the table is full.
    assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
    assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now).is_ok());
    for _ in 0..64 {
        assert_eq!(
            limiter.charge(&relay, &PeerId::random(), Unregistered, 1, now),
            Err(DropReason::AuthorRate)
        );
    }
    assert_eq!(limiter.tracked_authors(), 4, "fresh identities do not grow the table");

    // A registered author is bounded by the chain registry and always tracked.
    let member = PeerId::random();
    assert!(limiter.charge(&relay, &member, Registered, 1, now).is_ok());
    assert_eq!(limiter.tracked_authors(), 5);

    // Idle buckets are forgotten, making room for new authors again.
    let later = now + RATE_BUCKET_IDLE_FORGET;
    assert!(limiter.charge(&relay, &PeerId::random(), Unregistered, 1, later).is_ok());
    assert_eq!(limiter.tracked_authors(), 1);
}

/// Forgetting an idle bucket must not hand its owner tokens it had spent.
#[test]
fn default_tiers_refill_within_the_idle_forget_window() {
    let limits = RateLimits::defaults();
    for tier in [
        limits.direct_peer,
        limits.registered_author,
        limits.unregistered_author,
        limits.unregistered_total,
        limits.unregistered_forward,
        limits.global,
    ] {
        let window = RATE_BUCKET_IDLE_FORGET.as_secs() as i64;
        assert!(i64::from(tier.msg_burst) <= i64::from(tier.msg_per_sec) * window);
        assert!(tier.byte_burst <= tier.byte_per_sec * window);
    }
}

/// Verify admissions immediately update cached class totals.
#[tokio::test]
async fn cached_class_totals_count_admissions_immediately() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let limits = InboundLimits { global: Quota { rows: 2, bytes: 3000 }, ..SMALL };
    let member = |index: u8| {
        let peer = PeerId::random();
        gates.registry.record_committee_peer(&peer, Some(true), now);
        let _ = index;
        peer
    };

    // Nothing is inserted between evaluations: only the cache can know that
    // two rows are already on their way into the inbox.
    for sequence_number in 0..2 {
        let message = durable_bytes().await;
        let verdict =
            gates.evaluate(&local_db, &limits, &member(0), sequence_number, &message, now).await;
        assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
    }
    let message = durable_bytes().await;
    let verdict = gates.evaluate(&local_db, &limits, &member(1), 9, &message, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::GlobalQuota)));

    // Reload totals after cache expiry.
    let later = now + INBOX_CLASS_TOTALS_TTL;
    let verdict = gates.evaluate(&local_db, &limits, &member(2), 10, &message, later).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
}

#[tokio::test]
async fn binary_envelope_is_reserved_for_gen_circuits_from_verifiers() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let source = PeerId::random();

    // A small message wrapped in the binary envelope: well-formed, but it
    // is not the payload the envelope exists for.
    let message = committee_vote();
    let mut wrapped = b"GOATBIN1".to_vec();
    wrapped.extend(bincode::serialize(&message).unwrap());

    let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &wrapped, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::BinaryFromNonVerifier)));

    gates.registry.record_verifier_set(Some(vec![source.to_bytes()]), now);
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &wrapped, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::UnexpectedBinaryKind)));
}

/// A verifier's endorsement of the graph parameters.
fn verifier_endorsement() -> GOATMessage {
    use crate::messages::VerifierGraphParamsEndorsement;
    let keypair = test_keypair(9);
    let digest = bitcoin::secp256k1::Message::from_digest([5; 32]);
    GOATMessage::new(
        Actor::Committee,
        GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
            instance_id: Uuid::new_v4(),
            graph_id: Uuid::new_v4(),
            verifier_pubkey: bitcoin::PublicKey::new(keypair.public_key()),
            verifier_index: 0,
            canonical_graph_params_hash: [5; 32],
            signature: bitcoin::secp256k1::Secp256k1::new().sign_schnorr(&digest, &keypair),
        }),
    )
}

#[tokio::test]
async fn parameter_endorsements_come_from_the_verifier_set_once_it_is_loaded() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let (verifier, stranger) = (PeerId::random(), PeerId::random());
    // The stranger is registered (a committee peer), just not a verifier.
    gates.registry.record_committee_peer(&stranger, Some(true), now);
    let message = verifier_endorsement().serialize_message().await.unwrap();

    // Before the set is known nobody is turned away on it.
    let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 1, &message, now).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));

    gates.registry.record_verifier_set(Some(vec![verifier.to_bytes()]), now);
    let verdict = gates.evaluate(&local_db, &SMALL, &stranger, 2, &message, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::EndorsementFromNonVerifier)));
    let verdict = gates.evaluate(&local_db, &SMALL, &verifier, 1, &message, now).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
}

#[tokio::test]
async fn immediate_messages_are_rate_limited_per_sender() {
    use crate::messages::NodeInfo;

    let local_db = store::create_local_db("sqlite::memory:").await;
    let gates = TestGates::new(PeerRateLimiter::new(1.0, 0.0, 16));
    let now = Instant::now();
    let source = PeerId::random();
    let request = GOATMessage::new(
        Actor::All,
        GOATMessageContent::RequestNodeInfo(NodeInfo {
            peer_id: source.to_string(),
            actor: "Operator".to_string(),
            goat_addr: String::new(),
            btc_pub_key: String::new(),
            socket_addr: String::new(),
            node_name: String::new(),
            service_fee_rate: 0.0,
            available_peg_btc: "0".to_string(),
            ..Default::default()
        }),
    )
    .serialize_message()
    .await
    .unwrap();

    let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &request, now).await;
    assert!(matches!(verdict, InboundVerdict::Immediate(_)));
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &request, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ImmediateRateLimited)));
    let other = PeerId::random();
    let verdict = gates.evaluate(&local_db, &SMALL, &other, 1, &request, now).await;
    assert!(matches!(verdict, InboundVerdict::Immediate(_)), "limits are per sender");
}

/// Verify equivalent key encodings share one operator identity.
#[test]
fn operator_identity_ignores_how_the_key_is_spelled() {
    use crate::messages::{NodeInfo, sign_node_info_binding, verify_node_info_binding};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9; 32]).unwrap());
    let compressed = bitcoin::PublicKey::new(keypair.public_key());
    let mut other_parity = compressed.to_string();
    other_parity.replace_range(..2, if other_parity.starts_with("02") { "03" } else { "02" });
    let mut uncompressed = compressed;
    uncompressed.compressed = false;
    let spellings = [
        compressed.to_string(),
        compressed.to_string().to_uppercase(),
        other_parity,
        uncompressed.to_string(),
    ];

    let registry = PeerRegistry::default();
    let now = Instant::now();
    let mut keys = HashSet::new();
    let mut peers = Vec::new();
    for (index, spelling) in spellings.iter().enumerate() {
        let peer = PeerId::random();
        let issued_at = 100 + index as i64;
        let node_info = NodeInfo {
            peer_id: peer.to_string(),
            btc_pub_key: spelling.clone(),
            binding_sig: sign_node_info_binding(&peer.to_string(), spelling, issued_at, &keypair),
            binding_issued_at: issued_at,
            ..Default::default()
        };
        let verified = verify_node_info_binding(&node_info)
            .unwrap_or_else(|| panic!("{spelling} is a valid spelling of the key"));
        let operator = operator_key(&verified);
        keys.insert(operator);
        registry.observe_operator_binding(&peer, &operator, issued_at);
        if registry.plan_operator_refresh(&peer, &operator, now) {
            registry.record_operator_stake(&peer, &operator, Some(true), now);
        }
        peers.push(peer);
    }
    assert_eq!(keys.len(), 1, "every spelling is the same operator");
    let registered =
        peers.iter().filter(|peer| registry.sender_class(peer, now).is_registered()).count();
    assert_eq!(registered, 1, "one stake backs one peer id, however the key is written");
    assert!(registry.sender_class(peers.last().unwrap(), now).is_registered());
}

/// Verify equal timestamps cannot transfer ownership and key changes revoke prior registration.
#[test]
fn operator_key_changes_hands_only_forward_and_rebinding_revokes() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let (first, second) = (PeerId::random(), PeerId::random());
    let (staked, unstaked) = (key(1), key(2));

    assert!(!registry.observe_operator_binding(&first, &staked, 100));
    assert!(registry.plan_operator_refresh(&first, &staked, now));
    assert_eq!(registry.record_operator_stake(&first, &staked, Some(true), now), Some(true));

    registry.observe_operator_binding(&second, &staked, 100);
    assert!(registry.sender_class(&first, now).is_registered(), "same issue time: no change");
    assert!(!registry.plan_operator_refresh(&second, &staked, now));

    // Moving to an unstaked key gives up the confirmed one ...
    assert!(registry.observe_operator_binding(&first, &unstaked, 200));
    assert!(!registry.sender_class(&first, now).is_registered());
    // ... and the negative verdict for the new key is still handed back, so
    // the store is cleaned even though nothing "changed" for this binding.
    assert!(registry.plan_operator_refresh(&first, &unstaked, now));
    assert_eq!(registry.record_operator_stake(&first, &unstaked, Some(false), now), Some(false));
    // A verdict for the key the peer no longer holds is ignored.
    assert_eq!(registry.record_operator_stake(&first, &staked, Some(true), now), None);
}

/// A stored confirmation is restored only for the key it was made for.
#[tokio::test]
async fn stored_operator_confirmation_is_bound_to_its_key() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let now = Instant::now() + OPERATOR_STAKE_STALE_LIMIT;
    let (kept, rebound, member) = (PeerId::random(), PeerId::random(), PeerId::random());
    let (staked, unstaked) = (key(1), key(2));
    {
        let mut storage = local_db.acquire().await.unwrap();
        for peer in [&kept, &rebound] {
            storage
                .upsert_p2p_registered_peer(
                    &peer.to_string(),
                    REGISTERED_KIND_OPERATOR,
                    &hex::encode(if peer == &kept { staked } else { key(3) }),
                )
                .await
                .unwrap();
        }
        storage
            .upsert_p2p_registered_peer(&member.to_string(), REGISTERED_KIND_COMMITTEE, "")
            .await
            .unwrap();
    }
    // `rebound` was confirmed for key 3 but now presents a (validly signed)
    // binding for an unstaked key.
    let bindings = HashMap::from([(kept, (staked, 10)), (rebound, (unstaked, 20))]);
    let registry = PeerRegistry::default();
    for (peer, (operator, issued_at)) in &bindings {
        registry.observe_operator_binding(peer, operator, *issued_at);
    }
    let seeded = seed_registry_from_store(&local_db, &registry, &bindings, now).await.unwrap();
    assert_eq!(seeded, 2, "the kept operator and the committee member");
    assert_eq!(registry.sender_class(&kept, now), SenderClass::Registered);
    assert_eq!(registry.sender_class(&member, now), SenderClass::Committee);
    assert_eq!(registry.sender_class(&rebound, now), SenderClass::Unregistered);

    // The revocation a re-binding triggers removes the stored row.
    revoke_persisted_operator(&local_db, &rebound).await;
    let stored = local_db.acquire().await.unwrap().load_p2p_registered_peers().await.unwrap();
    assert!(!stored.iter().any(|(peer_id, _, _)| *peer_id == rebound.to_string()));
}

#[test]
fn committee_reserve_is_closed_to_other_senders() {
    use SenderClass::{Committee, Registered};
    let limits = InboundLimits { committee_reserve: Quota { rows: 2, bytes: 2000 }, ..SMALL };

    // Four rows from staked operators fill everything outside the reserve.
    let crowded = [usage(Registered, 4, 400, (0, 0))];
    assert_eq!(check_inbox_quota(Registered, 100, &crowded, &limits), Err(DropReason::GlobalQuota));
    assert_eq!(check_inbox_quota(Committee, 100, &crowded, &limits), Ok(()));
    // Committee rows do not count against the others' share.
    let committee_heavy = [usage(Committee, 3, 300, (0, 0)), usage(Registered, 2, 200, (0, 0))];
    assert_eq!(check_inbox_quota(Registered, 100, &committee_heavy, &limits), Ok(()));
    // The committee is still bounded by the global ceiling.
    let full = [usage(Committee, 6, 600, (0, 0))];
    assert_eq!(check_inbox_quota(Committee, 100, &full, &limits), Err(DropReason::GlobalQuota));
}

/// Verify a full gate rejects new live keys.
#[test]
fn gates_and_sets_refuse_new_keys_when_full_of_live_ones() {
    let now = Instant::now();
    let gate = CooldownGate::new(Duration::from_secs(60), 4);
    for index in 0..4 {
        assert!(gate.allow(&format!("key-{index}"), now));
    }
    for index in 4..64 {
        assert!(!gate.allow(&format!("key-{index}"), now + Duration::from_secs(1)));
    }
    assert_eq!(gate.len(), 4);
    assert!(gate.is_cooling("key-0", now + Duration::from_secs(1)));
    assert!(!gate.is_cooling("key-9", now + Duration::from_secs(1)), "never recorded");
    // Expired keys make room again, once the sweep interval has passed.
    assert!(gate.allow("late", now + Duration::from_secs(61)));
    assert_eq!(gate.len(), 1);
}

#[test]
fn global_rate_spends_its_burst_and_refills_at_its_rate() {
    let rate = GlobalRate::new(2.0, 1.0);
    let now = Instant::now();
    assert!(rate.allow(now));
    assert!(rate.allow(now));
    assert!(!rate.allow(now), "the burst is spent");
    assert!(rate.allow(now + Duration::from_secs(1)), "one token per second comes back");
    assert!(!rate.allow(now + Duration::from_secs(1)));
}

/// Verify future sequence numbers do not move the window.
#[test]
fn future_sequence_numbers_cannot_raise_the_mark() {
    let guard = ReplayGuard::default();
    let author = PeerId::random();
    let ahead = WALL_CLOCK + REPLAY_MAX_FUTURE.as_nanos() as u64;
    assert_eq!(guard.admit(&author, Some(ahead + 1), WALL_CLOCK), Err(DropReason::FutureSequence));
    assert_eq!(
        guard.admit(&author, Some(ahead - REPLAY_WINDOW), WALL_CLOCK),
        Ok(()),
        "nothing was recorded: the window did not move up to the refused number"
    );
    assert_eq!(guard.admit(&author, Some(ahead), WALL_CLOCK), Ok(()), "inside the tolerance");

    // The corrected clock numbers lower than the mark: refused, and surfaced
    // for the operator once it keeps happening.
    assert!(guard.take_lockout_suspects().is_empty());
    for offset in 0..REPLAY_LOCKOUT_SUSPECT_REJECTIONS as u64 {
        assert_eq!(
            guard.admit(&author, Some(WALL_CLOCK - REPLAY_WINDOW * 2 + offset), WALL_CLOCK),
            Err(DropReason::ReplayedSequence)
        );
    }
    assert_eq!(guard.take_lockout_suspects(), vec![(author, REPLAY_LOCKOUT_SUSPECT_REJECTIONS)]);
    assert!(guard.take_lockout_suspects().is_empty(), "reported once per tick");
}

#[test]
fn direct_peer_is_banned_at_the_strike_limit_and_released_later() {
    let strikes = DirectPeerStrikes::default();
    let now = Instant::now();
    let (flooder, bystander) = (PeerId::random(), PeerId::random());
    for _ in 0..(STRIKE_LIMIT - 1) {
        assert!(!strikes.strike(&flooder, now));
    }
    assert!(!strikes.strike(&bystander, now));
    assert!(strikes.strike(&flooder, now), "the limit is reached exactly once");
    assert!(!strikes.strike(&flooder, now), "already banned");
    assert!(strikes.take_expired_bans(now).is_empty());
    assert_eq!(strikes.take_expired_bans(now + STRIKE_BAN), vec![flooder]);

    // Strikes spread thinner than the window never add up.
    let slow = PeerId::random();
    for round in 0..(STRIKE_LIMIT * 2) {
        assert!(!strikes.strike(&slow, now + STRIKE_WINDOW * round));
    }

    // Only verdicts that do not depend on this node's state are blamed on
    // the neighbour; and an unanswered lookup is not "known unregistered".
    assert!(DropReason::Undecodable.blames_direct_peer());
    assert!(DropReason::UnexpectedBinaryKind.blames_direct_peer());
    for local in [
        DropReason::SenderQuota,
        DropReason::ReplayedSequence,
        // An honest relay earns this one just by being the only neighbour.
        DropReason::DirectPeerRate,
        // The JSON ceiling is configurable, so nodes may disagree on it.
        DropReason::OversizedJson,
        DropReason::BinaryFromNonVerifier,
    ] {
        assert!(!local.blames_direct_peer(), "{local:?} depends on this node");
    }
    assert!(!strikes.is_banned(&bystander, now));
    let banned = PeerId::random();
    for _ in 0..STRIKE_LIMIT {
        strikes.strike(&banned, now);
    }
    assert!(strikes.is_banned(&banned, now), "a ban holds against reconnecting");
    assert!(!strikes.is_banned(&banned, now + STRIKE_BAN));
    let registry = PeerRegistry::default();
    assert!(!registry.is_known_unregistered(&flooder, now));
    registry.record_committee_peer(&flooder, Some(false), now);
    assert!(registry.is_known_unregistered(&flooder, now));
    registry.record_committee_peer(&bystander, Some(true), now);
    assert!(!registry.is_known_unregistered(&bystander, now));
}

/// A durable message no handler of this node's role acts on is relayed, but
/// takes no inbox row and no quota.
#[tokio::test]
async fn messages_for_another_role_are_forwarded_without_being_stored() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let now = Instant::now();
    let source = PeerId::random();
    gates.registry.record_committee_peer(&source, Some(true), now);
    let vote = durable_bytes().await;

    gates.local_actor = Actor::Verifier;
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &vote, now).await;
    assert!(matches!(verdict, InboundVerdict::Forward), "a verifier node has no handler");
    gates.local_actor = Actor::Committee;
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &vote, now).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { .. }));
}

/// Every kind `dispatch` or an aggregate handles is kept by `handled_by`
/// for the roles that handle it, and relayed for the others.
#[test]
fn handled_kinds_follow_the_role_table() {
    use crate::messages::MessageKind;

    let roles = [Actor::Committee, Actor::Operator, Actor::Verifier, Actor::Watchtower];
    // Immediate kinds reach every role's dispatch.
    for kind in
        [MessageKind::GraphSetupAck, MessageKind::RequestNodeInfo, MessageKind::ResponseNodeInfo]
    {
        for role in &roles {
            assert!(kind.handled_by(role), "{kind} for {role}");
        }
    }
    // The PeginConfirm round is the committee's.
    for kind in [
        MessageKind::PeginConfirmNonce,
        MessageKind::PeginConfirmNonceConsensus,
        MessageKind::PeginConfirmPartialSig,
    ] {
        assert!(kind.handled_by(&Actor::Committee), "{kind}");
        for role in [Actor::Operator, Actor::Verifier, Actor::Watchtower] {
            assert!(!kind.handled_by(&role), "{kind} for {role}");
        }
    }
    // Graph-phase kinds follow the Graph aggregate's routing table.
    assert!(MessageKind::InitGraph.handled_by(&Actor::Verifier));
    assert!(!MessageKind::InitGraph.handled_by(&Actor::Committee));
    assert!(MessageKind::GraphFinalize.handled_by(&Actor::Watchtower));
}

/// Verify committee-only reserves in shared rate tiers.
#[test]
fn shared_rate_tiers_keep_a_reserve_for_the_committee() {
    let tier = TierRate { msg_burst: 8, msg_per_sec: 0, byte_burst: 8_000, byte_per_sec: 0 };
    let roomy = TierRate { msg_burst: 1_000, msg_per_sec: 0, byte_burst: 1 << 30, byte_per_sec: 0 };
    let limiter = InboundRateLimiter::new(RateLimits {
        direct_peer: roomy,
        registered_author: roomy,
        unregistered_author: roomy,
        unregistered_total: roomy,
        unregistered_forward: roomy,
        global: tier,
        committee_reserve: 0.25,
        max_tracked_peers: 16,
    });
    let now = Instant::now();
    let relay = PeerId::random();
    use SenderClass::{Committee, Registered, Unregistered};

    // Six of eight messages are open to everyone ...
    for _ in 0..6 {
        assert!(limiter.charge(&relay, &PeerId::random(), Registered, 100, now).is_ok());
    }
    assert_eq!(
        limiter.charge(&relay, &PeerId::random(), Registered, 100, now),
        Err(DropReason::GlobalRate)
    );
    assert_eq!(
        limiter.charge(&relay, &PeerId::random(), Unregistered, 100, now),
        Err(DropReason::GlobalRate)
    );
    // ... and the last two only to the committee.
    for _ in 0..2 {
        assert!(limiter.charge(&relay, &PeerId::random(), Committee, 100, now).is_ok());
    }
    assert_eq!(
        limiter.charge(&relay, &PeerId::random(), Committee, 100, now),
        Err(DropReason::GlobalRate)
    );
}

/// Verify unregistered forward-only traffic is rate-limited.
#[tokio::test]
async fn forwarding_for_unregistered_authors_is_budgeted() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    // A committee node relays the operator's recruitment to verifiers.
    let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let tier = TierRate { msg_burst: 2, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
    gates.rate_limiter = InboundRateLimiter::new(RateLimits {
        unregistered_forward: tier,
        ..RateLimits::defaults()
    });
    let now = Instant::now();

    for sequence_number in 0..2 {
        let data = init_graph().serialize_message().await.unwrap();
        let verdict =
            gates.evaluate(&local_db, &SMALL, &PeerId::random(), sequence_number, &data, now).await;
        assert!(matches!(verdict, InboundVerdict::Forward));
    }
    let data = init_graph().serialize_message().await.unwrap();
    let verdict = gates.evaluate(&local_db, &SMALL, &PeerId::random(), 9, &data, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ForwardRate)));

    let member = PeerId::random();
    gates.registry.record_committee_peer(&member, Some(true), now);
    let verdict = gates.evaluate(&local_db, &SMALL, &member, 1, &data, now).await;
    assert!(matches!(verdict, InboundVerdict::Forward), "registered authors are not charged");
}

/// A durable message this role handles is relayed, not stored, while its
/// author is unregistered; once the author is known it is stored.
#[tokio::test]
async fn durable_messages_from_unregistered_authors_are_relayed_not_stored() {
    let local_db = store::create_local_db("sqlite::memory:").await;
    let mut gates = TestGates::new(PeerRateLimiter::new(10.0, 1.0, 16));
    let tier = TierRate { msg_burst: 1, msg_per_sec: 0, byte_burst: 1 << 20, byte_per_sec: 0 };
    gates.rate_limiter = InboundRateLimiter::new(RateLimits {
        unregistered_forward: tier,
        ..RateLimits::defaults()
    });
    let now = Instant::now();
    let source = PeerId::random();
    let vote = durable_bytes().await;

    let verdict = gates.evaluate(&local_db, &SMALL, &source, 1, &vote, now).await;
    assert!(matches!(verdict, InboundVerdict::Forward));
    // The relay budget is the unregistered one; past it the message is dropped.
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 2, &vote, now).await;
    assert!(matches!(verdict, InboundVerdict::Drop(DropReason::ForwardRate)));
    // Nothing was queued for the quota.
    assert!(
        local_db.acquire().await.unwrap().engine_inbox_class_totals().await.unwrap().is_empty()
    );

    gates.registry.record_committee_peer(&source, Some(true), now);
    let verdict = gates.evaluate(&local_db, &SMALL, &source, 3, &vote, now).await;
    assert!(matches!(verdict, InboundVerdict::Enqueue { class: SenderClass::Committee, .. }));
}

/// Verify neighbour discovery is independent of author discovery.
#[test]
fn neighbour_lookups_have_their_own_budget() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    registry.record_verifier_set(Some(vec![]), now);
    for _ in 0..(COMMITTEE_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
        let author = PeerId::random();
        if registry.plan_refresh(Some(&author), now).committee_peer {
            registry.record_committee_peer(&author, Some(false), now);
        }
    }
    let neighbour = PeerId::random();
    assert!(!registry.plan_refresh(Some(&neighbour), now).committee_peer, "budget spent");
    assert!(registry.plan_neighbour_lookup(&neighbour, now));

    // Verify refused peers cannot consume neighbour discovery budget.
    let mut refused = 0;
    for _ in 0..(REFUSED_PEER_LOOKUPS_PER_MINUTE * 2) {
        let peer = PeerId::random();
        if registry.plan_refused_peer_lookup(&peer, now) {
            refused += 1;
            registry.record_committee_peer(&peer, Some(false), now);
        }
    }
    assert_eq!(refused, REFUSED_PEER_LOOKUPS_PER_MINUTE);
    assert!(registry.plan_neighbour_lookup(&PeerId::random(), now));
}

/// Verify committee-only lookup does not claim verifier-set refresh.
#[test]
fn neighbour_lookup_does_not_claim_the_verifier_set() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    // The verifier set has never been fetched, so it is due.
    assert!(registry.plan_neighbour_lookup(&PeerId::random(), now));
    assert!(registry.plan_refused_peer_lookup(&PeerId::random(), now));
    assert!(
        registry.plan_refresh(None, now).verifier_set,
        "the verifier set is still there to be claimed by a caller that fetches it"
    );
}

/// Verify configured bindings still require confirmed stake.
#[test]
fn trusted_operator_binding_needs_the_chain_but_not_the_budget() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    // Spend the operator discovery budget on self-signed bindings.
    for index in 0..(OPERATOR_DISCOVERY_LOOKUPS_PER_MINUTE * 2) {
        let (sybil, sybil_key) = (PeerId::random(), key(index + 10));
        registry.observe_operator_binding(&sybil, &sybil_key, 1);
        if registry.plan_operator_refresh(&sybil, &sybil_key, now) {
            registry.record_operator_stake(&sybil, &sybil_key, Some(false), now);
        }
    }
    let (newcomer, newcomer_key) = (PeerId::random(), key(1));
    registry.observe_operator_binding(&newcomer, &newcomer_key, 1);
    assert!(!registry.plan_operator_refresh(&newcomer, &newcomer_key, now), "budget spent");

    let (trusted, trusted_key) = (PeerId::random(), key(2));
    assert_eq!(registry.trust_operator_binding(&trusted, &trusted_key), Ok(()));
    assert!(!registry.sender_class(&trusted, now).is_registered(), "configured is not staked");
    let due = registry.plan_due_operator_refreshes(now);
    assert!(due.contains(&(trusted, trusted_key)), "looked up despite the spent budget");
    assert!(
        due.iter().all(|(_, operator)| *operator == trusted_key),
        "keys the chain said are not staked are not swept again, and the newcomer still \
         has no budget: {} due",
        due.len()
    );
    registry.record_operator_stake(&trusted, &trusted_key, Some(true), now);
    assert_eq!(registry.sender_class(&trusted, now), SenderClass::Registered);

    // The operator's own signed announcement later keeps the verdict ...
    registry.observe_operator_binding(&trusted, &trusted_key, 500);
    assert!(registry.sender_class(&trusted, now).is_registered());
    // ... and if it moves to another peer id, its signature outranks the
    // static configuration.
    let moved = PeerId::random();
    registry.observe_operator_binding(&moved, &trusted_key, 600);
    assert!(!registry.sender_class(&trusted, now).is_registered());
}

/// Verify signed bindings take precedence over configuration.
#[test]
fn configured_binding_does_not_override_a_signed_one() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let (operator, other_peer) = (PeerId::random(), PeerId::random());
    let (signed_key, configured_key) = (key(1), key(2));

    // Restored from the store: the operator's own signed binding, confirmed.
    registry.seed_verified_operator(&operator, &signed_key, 100, now);
    let now = now + Duration::from_secs(1);
    assert!(registry.sender_class(&operator, now).is_registered());

    // The config still names an older key for that peer ...
    assert_eq!(
        registry.trust_operator_binding(&operator, &configured_key),
        Err(TrustedBindingConflict::PeerBoundToAnotherKey(signed_key))
    );
    // ... or names the operator's key under a peer id it has moved away from.
    assert_eq!(
        registry.trust_operator_binding(&other_peer, &signed_key),
        Err(TrustedBindingConflict::KeyBoundToAnotherPeer(operator))
    );
    assert!(registry.sender_class(&operator, now).is_registered(), "the signed binding stands");
    assert!(!registry.sender_class(&other_peer, now).is_registered());

    // Agreeing with the signed binding keeps its verdict and adds the trust.
    assert_eq!(registry.trust_operator_binding(&operator, &signed_key), Ok(()));
    assert!(registry.sender_class(&operator, now).is_registered());

    // The same peer configured twice with different keys: first one stands.
    let fresh = PeerId::random();
    assert_eq!(registry.trust_operator_binding(&fresh, &key(3)), Ok(()));
    assert_eq!(
        registry.trust_operator_binding(&fresh, &key(4)),
        Err(TrustedBindingConflict::PeerBoundToAnotherKey(key(3)))
    );
}

/// Verify clock leads are recorded within and beyond tolerance.
#[test]
fn clock_leads_are_reported_per_author_and_then_forgotten() {
    let guard = ReplayGuard::default();
    let (slightly_ahead, far_ahead, on_time) =
        (PeerId::random(), PeerId::random(), PeerId::random());
    let minute = Duration::from_secs(60).as_nanos() as u64;

    assert_eq!(guard.admit(&on_time, Some(WALL_CLOCK - minute), WALL_CLOCK), Ok(()));
    assert_eq!(guard.admit(&slightly_ahead, Some(WALL_CLOCK + 2 * minute), WALL_CLOCK), Ok(()));
    assert_eq!(guard.admit(&slightly_ahead, Some(WALL_CLOCK + 3 * minute), WALL_CLOCK), Ok(()));
    assert_eq!(
        guard.admit(&far_ahead, Some(WALL_CLOCK + 30 * minute), WALL_CLOCK),
        Err(DropReason::FutureSequence)
    );

    let mut leads = guard.take_clock_leads();
    leads.sort_by_key(|(_, lead)| *lead);
    assert_eq!(
        leads,
        vec![
            (slightly_ahead, Duration::from_secs(3 * 60)),
            (far_ahead, Duration::from_secs(30 * 60))
        ],
        "the largest lead per author; an author on time is not listed"
    );
    assert!(guard.take_clock_leads().is_empty());
}

/// Verify only successful recovery closes the gate.
/// A "no" that has gone stale is not grounds for acting against a neighbour.
#[test]
fn a_stale_negative_is_not_known_unregistered() {
    let registry = PeerRegistry::default();
    let now = Instant::now();
    let peer = PeerId::random();
    registry.record_committee_peer(&peer, Some(false), now);
    assert!(registry.is_known_unregistered(&peer, now));
    assert!(!registry.is_known_unregistered(&peer, now + COMMITTEE_NEGATIVE_TTL));
}

#[test]
fn trusted_operator_bindings_are_parsed_strictly() {
    use crate::env::parse_trusted_operator_bindings;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[9; 32]).unwrap());
    let pubkey = bitcoin::PublicKey::new(keypair.public_key());
    let xonly = bitcoin::XOnlyPublicKey::from(pubkey).serialize();
    let (first, second) = (PeerId::random(), PeerId::random());
    let value = format!(
        " {first}={pubkey} , not-a-binding, {second} = {} ,{first}=zz,",
        pubkey.to_string().to_uppercase()
    );
    assert_eq!(
        parse_trusted_operator_bindings(&value),
        vec![(first, xonly), (second, xonly)],
        "malformed entries are skipped, and every spelling is the same key"
    );
    assert!(parse_trusted_operator_bindings("").is_empty());
}
