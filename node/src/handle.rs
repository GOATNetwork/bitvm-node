use crate::action::*;
use crate::env::{
    COMMITTEE_INSTANCE_KEYS_DIR, get_babe_gc_asset_paths, get_bitvm_key, get_node_goat_address,
    get_peer_id, get_soldering_proof_payload_store_path, get_verifier_candidate_backup_count,
    get_verifier_candidate_collection_window_secs, is_relayer,
};
use crate::error::SpecialError;
use crate::metrics_service::MetricsState;
use crate::middleware::AllBehaviours;
use crate::rpc_service::current_time_secs;
use crate::scheduled_tasks::graph_maintenance_tasks::ChallengeSubStatus;
use crate::soldering_payload_store::{
    read_soldering_proof_store_payload, soldering_proof_payload_store_path,
};
use crate::utils::*;
use anyhow::{Context, Result, anyhow, bail, ensure};
use ark_serialize::CanonicalSerialize;
use bitcoin::{Amount, OutPoint, Txid, hashes::Hash, key::Keypair};
use bitcoin::{PublicKey, XOnlyPublicKey};
use bitvm_lib::actors::Actor;
use bitvm_lib::babe_adapter::{
    BABE_M_CC, BABE_N_CC, BabeBundleBuilder, BabeChallengeAssertWitness, BabeProverState,
    CACSetupPackage, ChallengeAssertWitnessRaw, CompactSolderingProofPayload,
    FinalizedInstanceData, SolderingData, TxAssertWitness, WOTS_SIG_COUNT, assert_wots_message,
    build_assert_witness, build_real_challenge_assert_witness, build_real_setup_package,
    derive_finalized_indices, expand_compact_soldering_proof_payload, extract_gc_circuit_data,
    open_real_setup_and_solder, recover_operator_proof_from_assert_witness,
    recover_real_wrongly_challenged_witness, verify_real_setup,
};
use bitvm_lib::committee::*;
use bitvm_lib::keys::*;
use bitvm_lib::operator::*;
use bitvm_lib::types::{
    BitvmGcCircuitData, BitvmGcGraph, BitvmGcInstanceParameters, SimplifiedBitvmGcGraph,
};
use bitvm_lib::verifier::*;
use client::goat_chain::{DisproveTxType, PeginStatus, WithdrawStatus};
use client::graphs::graph_query::BridgeInRequestEvent;
use client::http_client::async_client::HttpAsyncClient;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::pre_signed_musig2::verify_public_nonce;
use goat::wots::{Wots, Wots96};
use libp2p::gossipsub::MessageId;
use libp2p::{PeerId, Swarm};
use secp256k1::{Message as SecpMessage, SECP256K1};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use store::localdb::LocalDB;
use store::{GoatTxType, GraphStatus, SerializableTxid};
use uuid::Uuid;

pub struct HandlerContext<'a> {
    pub swarm: &'a mut Swarm<AllBehaviours>,
    pub local_db: &'a LocalDB,
    pub btc_client: &'a Arc<BTCClient>,
    pub goat_client: &'a Arc<GOATClient>,
    pub http_client: &'a HttpAsyncClient,
    pub soldering_builder: &'a Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: &'a MetricsState,
    pub actor: Actor,
    pub from_peer_id: PeerId,
    pub id: MessageId,
    pub is_self_peer: bool,
}

/// Owned resources for work that must not run on the swarm event loop. It
/// deliberately excludes `Swarm`: heavy work persists its follow-up protocol
/// notifications to the durable P2P outbox instead.
pub(crate) struct HeavyTaskContext {
    pub local_db: LocalDB,
    pub btc_client: Arc<BTCClient>,
    pub goat_client: Arc<GOATClient>,
    pub soldering_builder: Option<Arc<BabeBundleBuilder>>,
    pub metrics_state: MetricsState,
    pub from_peer_id: PeerId,
}

pub(crate) enum HeavyTask {
    GenerateVerifierSetup(InitGraph),
    GenerateSolderingProof(CutCircuits),
    ValidateVerifierGraph(Box<CreateGraph>),
    VerifySolderingProof(SolderingProofReady),
}

impl HeavyTask {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::GenerateVerifierSetup(_) => "generate_verifier_setup",
            Self::GenerateSolderingProof(_) => "generate_soldering_proof",
            Self::ValidateVerifierGraph(_) => "validate_verifier_graph",
            Self::VerifySolderingProof(_) => "verify_soldering_proof",
        }
    }

    pub(crate) fn message_type(&self) -> &'static str {
        match self {
            Self::GenerateVerifierSetup(_) => "InitGraph",
            Self::GenerateSolderingProof(_) => "CutCircuits",
            Self::ValidateVerifierGraph(_) => "CreateGraph",
            Self::VerifySolderingProof(_) => "SolderingProofReady",
        }
    }

    pub(crate) fn graph_id(&self) -> Uuid {
        match self {
            Self::GenerateVerifierSetup(message) => message.graph_id,
            Self::GenerateSolderingProof(message) => message.graph_id,
            Self::ValidateVerifierGraph(message) => message.graph_id,
            Self::VerifySolderingProof(message) => message.graph_id,
        }
    }
}

pub(crate) fn heavy_task_from_content(
    content: &GOATMessageContent,
    actor: &Actor,
) -> Option<HeavyTask> {
    match (content, actor) {
        (GOATMessageContent::InitGraph(message), Actor::Verifier) => {
            Some(HeavyTask::GenerateVerifierSetup(message.clone()))
        }
        (GOATMessageContent::CutCircuits(message), Actor::Verifier) => {
            Some(HeavyTask::GenerateSolderingProof(message.clone()))
        }
        (GOATMessageContent::CreateGraph(message), Actor::Verifier) => {
            Some(HeavyTask::ValidateVerifierGraph(Box::new(message.clone())))
        }
        (GOATMessageContent::SolderingProofReady(message), Actor::Operator) => {
            Some(HeavyTask::VerifySolderingProof(message.clone()))
        }
        _ => None,
    }
}

pub(crate) fn is_heavy_task_message_type(message_type: &str, actor: &Actor) -> bool {
    matches!(
        (message_type, actor),
        ("SolderingProofReady", Actor::Operator)
            | ("InitGraph" | "CutCircuits", Actor::Verifier)
            | ("CreateGraph", Actor::Verifier)
    )
}

pub(crate) async fn run_heavy_task(context: &HeavyTaskContext, task: HeavyTask) -> Result<()> {
    match task {
        HeavyTask::GenerateVerifierSetup(message) => {
            handle_init_graph_verifier(context, message).await
        }
        HeavyTask::GenerateSolderingProof(message) => {
            handle_cut_circuits_verifier(
                context,
                message.instance_id,
                message.graph_id,
                &message.verifier_pubkey,
                message.candidate_index,
                &message.selected_circuit_indexes,
            )
            .await
        }
        HeavyTask::ValidateVerifierGraph(message) => {
            handle_create_graph_verifier(
                context,
                message.instance_id,
                message.graph_id,
                message.graph_nonce,
                &message.graph,
            )
            .await
        }
        HeavyTask::VerifySolderingProof(message) => {
            handle_soldering_proof_ready_operator(
                context,
                message.instance_id,
                message.graph_id,
                message.candidate_index,
                message.payload_hash,
                message.total_len,
            )
            .await
        }
    }
}

fn committee_instance_keys_envelope_path(instance_id: Uuid) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(COMMITTEE_INSTANCE_KEYS_DIR);
    path.push(format!("{instance_id}.json"));
    path
}

fn is_io_not_found_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
    })
}

fn load_or_create_committee_instance_keypair(
    committee_master_key: &CommitteeMasterKey,
    instance_id: Uuid,
) -> Result<bitcoin::key::Keypair> {
    let envelope_path = committee_instance_keys_envelope_path(instance_id);
    match committee_master_key.load_instance_keypair(instance_id, &envelope_path) {
        Ok(keypair) => Ok(keypair),
        Err(load_err) => {
            if !is_io_not_found_error(&load_err) {
                return Err(load_err).with_context(|| {
                    format!(
                        "load committee instance keypair failed for {} at {} (refuse auto-overwrite for non-missing envelope)",
                        instance_id,
                        envelope_path.display()
                    )
                });
            }
            tracing::info!(
                "committee instance key not found for {} at {}: {}, creating new envelope",
                instance_id,
                envelope_path.display(),
                load_err
            );
            committee_master_key
                .create_instance_keypair_envelope(instance_id, &envelope_path)
                .with_context(|| {
                    format!(
                        "create committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                })?;
            committee_master_key.load_instance_keypair(instance_id, &envelope_path).with_context(
                || {
                    format!(
                        "reload committee instance key envelope failed for {} at {}",
                        instance_id,
                        envelope_path.display()
                    )
                },
            )
        }
    }
}

pub async fn dispatch(ctx: &mut HandlerContext<'_>, content: &GOATMessageContent) -> Result<()> {
    match (content, &ctx.actor) {
        (
            GOATMessageContent::GraphSetupAck(GraphSetupAck {
                outbox_id,
                acknowledger_peer_id,
                ..
            }),
            _,
        ) => {
            if acknowledger_peer_id != &ctx.from_peer_id.to_string() {
                tracing::warn!(
                    outbox_id,
                    from_peer_id = %ctx.from_peer_id,
                    acknowledger_peer_id,
                    "Ignore GraphSetupAck with mismatched source peer"
                );
                return Ok(());
            }
            let acknowledged = ctx
                .local_db
                .acquire()
                .await?
                .acknowledge_p2p_outbox_message(outbox_id, acknowledger_peer_id)
                .await?;
            tracing::debug!(
                outbox_id,
                from_peer_id = %ctx.from_peer_id,
                acknowledged,
                "processed GraphSetupAck"
            );
            Ok(())
        }
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                ..
            }),
            Actor::Committee,
        ) => {
            handle_pegin_request_committee(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
            )
            .await
        }
        (
            GOATMessageContent::PeginRequest(PeginRequest {
                instance_id,
                pegin_request_tx_hash,
                pegin_request_height,
                ..
            }),
            _,
        ) => {
            handle_pegin_request_default(
                ctx,
                *instance_id,
                pegin_request_tx_hash,
                *pegin_request_height,
            )
            .await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), Actor::Operator) => {
            handle_confirm_instance_operator(ctx, *instance_id).await
        }
        (GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }), _) => {
            handle_confirm_instance_default(ctx, *instance_id).await
        }
        (
            GOATMessageContent::GenCircuits(GenCircuits {
                instance_id,
                graph_id,
                verifier_pubkey,
                setup_package,
            }),
            Actor::Operator,
        ) => {
            handle_gen_circuits_operator(
                ctx,
                *instance_id,
                *graph_id,
                verifier_pubkey,
                setup_package,
            )
            .await
        }
        (content, actor) if heavy_task_from_content(content, actor).is_some() => {
            bail!("heavy task must be dispatched through the durable P2P inbox")
        }
        (
            GOATMessageContent::CreateGraph(CreateGraph {
                instance_id,
                graph_id,
                graph_nonce,
                graph,
            }),
            Actor::Committee,
        ) => {
            handle_create_graph_committee(
                ctx,
                *instance_id,
                *graph_id,
                *graph_nonce,
                graph,
                content,
            )
            .await
        }
        (
            GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
                instance_id,
                graph_id,
                verifier_pubkey,
                verifier_index,
                canonical_graph_params_hash,
                signature,
            }),
            Actor::Committee,
        ) => {
            handle_verifier_graph_params_endorsement_committee(
                ctx,
                *instance_id,
                *graph_id,
                verifier_pubkey,
                *verifier_index,
                *canonical_graph_params_hash,
                signature,
                content,
            )
            .await
        }
        (
            GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonces,
                nonce_sigs,
            }),
            Actor::Committee,
        ) => {
            handle_nonce_generation_committee(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                pub_nonces,
                nonce_sigs,
                content,
            )
            .await
        }
        (
            GOATMessageContent::NonceGeneration(NonceGeneration {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonces,
                nonce_sigs,
            }),
            Actor::Operator,
        ) => {
            handle_nonce_generation_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                pub_nonces,
                nonce_sigs,
            )
            .await
        }
        (
            GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                consensus_hash,
                signature,
            }),
            Actor::Committee,
        ) => {
            handle_agg_nonce_consensus_committee(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                *consensus_hash,
                signature,
                content,
            )
            .await
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
            }),
            Actor::Committee,
        ) => {
            handle_committee_presign_committee(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
                content,
            )
            .await
        }
        (
            GOATMessageContent::CommitteePresign(CommitteePresign {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
            }),
            Actor::Operator,
        ) => {
            handle_committee_presign_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_partial_sigs,
                agg_nonces,
                content,
            )
            .await
        }
        (
            GOATMessageContent::EndorseGraph(EndorseGraph {
                instance_id,
                graph_id,
                committee_pubkey: received_committee_pubkey,
                committee_sig_for_graph,
                committee_sig_for_params,
                committee_evm_address,
            }),
            Actor::Operator,
        ) => {
            handle_endorse_graph_operator(
                ctx,
                *instance_id,
                *graph_id,
                received_committee_pubkey,
                committee_sig_for_graph,
                committee_sig_for_params,
                committee_evm_address,
            )
            .await
        }
        (
            GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce,
                graph,
                endorse_sigs,
                params_endorse_sigs,
            }),
            Actor::Committee,
        ) => {
            handle_graph_finalize_committee(
                ctx,
                *instance_id,
                *graph_id,
                *graph_nonce,
                graph,
                endorse_sigs,
                params_endorse_sigs,
            )
            .await
        }
        (
            GOATMessageContent::GraphFinalize(GraphFinalize {
                instance_id,
                graph_id,
                graph_nonce,
                graph,
                endorse_sigs,
                params_endorse_sigs,
            }),
            _,
        ) => {
            handle_graph_finalize_default(
                ctx,
                *instance_id,
                *graph_id,
                *graph_nonce,
                graph,
                endorse_sigs,
                params_endorse_sigs,
            )
            .await
        }
        (
            GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                pub_nonce,
                nonce_sig,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_nonce_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                pub_nonce,
                nonce_sig,
                content,
            )
            .await
        }
        (
            GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                consensus_hash,
                signature,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_nonce_consensus_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                *consensus_hash,
                signature,
                content,
            )
            .await
        }
        (
            GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
                instance_id,
                committee_pubkey: received_committee_pubkey,
                partial_sig,
                endorse_sig,
            }),
            Actor::Committee,
        ) => {
            handle_pegin_confirm_partial_sig_committee(
                ctx,
                *instance_id,
                received_committee_pubkey,
                partial_sig,
                endorse_sig,
                content,
            )
            .await
        }
        (GOATMessageContent::PostReady(PostReady { instance_id }), Actor::Committee) => {
            handle_post_ready(ctx, *instance_id).await
        }
        (
            GOATMessageContent::KickoffReady(KickoffReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_kickoff_ready_operator(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Committee,
        ) => handle_kickoff_sent_committee(ctx, *instance_id, *graph_id, content).await,
        (
            GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }),
            Actor::Verifier,
        ) => handle_kickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::KickoffSent(KickoffSent { instance_id, graph_id }), _) => {
            handle_kickoff_sent_default(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }),
            Actor::Verifier,
        ) => handle_prekickoff_sent_verifier(ctx, *instance_id, *graph_id, content).await,
        (GOATMessageContent::PreKickoffSent(PreKickoffSent { instance_id, graph_id }), _) => {
            handle_prekickoff_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::ChallengeSent(ChallengeSent {
                instance_id,
                graph_id,
                challenge_txid,
            }),
            Actor::Operator,
        ) => {
            handle_challenge_sent_operator(ctx, *instance_id, *graph_id, *challenge_txid, content)
                .await
        }
        (GOATMessageContent::ChallengeSent(ChallengeSent { instance_id, graph_id, .. }), _) => {
            handle_challenge_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::WatchtowerChallengeInitSent(WatchtowerChallengeInitSent {
                instance_id,
                graph_id,
            }),
            Actor::Watchtower,
        ) => {
            handle_watchtower_challenge_init_sent_watchtower(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::WatchtowerChallengeSent(WatchtowerChallengeSent {
                instance_id,
                graph_id,
                watchtower_index,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *watchtower_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WatchtowerChallengeTimeout(WatchtowerChallengeTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_watchtower_challenge_timeout_operator(ctx, *instance_id, *graph_id, content)
                .await
        }
        (GOATMessageContent::NackReady(NackReady { instance_id, graph_id }), Actor::Verifier) => {
            handle_nack_ready_verifier(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinReady(OperatorCommitPubinReady {
                instance_id,
                graph_id,
            }),
            Actor::Operator,
        ) => {
            handle_operator_commit_pubin_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (
            GOATMessageContent::OperatorCommitPubinTimeout(OperatorCommitPubinTimeout {
                instance_id,
                graph_id,
            }),
            Actor::Verifier,
        ) => {
            handle_operator_commit_pubin_timeout_verifier(ctx, *instance_id, *graph_id, content)
                .await
        }
        (
            GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
            Actor::Operator,
        ) => handle_assert_ready_operator(ctx, *instance_id, *graph_id).await,
        (
            GOATMessageContent::AssertSent(AssertSent { instance_id, graph_id, assert_txid }),
            Actor::Verifier,
        ) => handle_assert_sent_verifier(ctx, *instance_id, *graph_id, *assert_txid, content).await,
        (
            GOATMessageContent::ChallengeAssertSent(ChallengeAssertSent {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                ..
            }),
            Actor::Operator,
        ) => {
            handle_challenge_assert_sent_operator(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::WronglyChallengeTimeout(WronglyChallengeTimeout {
                instance_id,
                graph_id,
                challenge_assert_txid,
                verifier_index,
                ..
            }),
            Actor::Verifier,
        ) => {
            handle_wrongly_challenge_timeout_verifier(
                ctx,
                *instance_id,
                *graph_id,
                *challenge_assert_txid,
                *verifier_index,
                content,
            )
            .await
        }
        (
            GOATMessageContent::DisproveSent(DisproveSent {
                instance_id,
                graph_id,
                disprove_type,
                index,
                challenge_finish_txid,
                ..
            }),
            Actor::Committee,
        ) => {
            handle_disprove_sent_committee(
                ctx,
                *instance_id,
                *graph_id,
                *disprove_type,
                *index,
                *challenge_finish_txid,
                content,
            )
            .await
        }
        (GOATMessageContent::DisproveSent(DisproveSent { instance_id, graph_id, .. }), _) => {
            handle_disprove_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take1Ready(Take1Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take1_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take1_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take1Sent(Take1Sent { instance_id, graph_id }), _) => {
            handle_take1_sent_default(ctx, *instance_id, *graph_id).await
        }
        (GOATMessageContent::Take2Ready(Take2Ready { instance_id, graph_id }), Actor::Operator) => {
            handle_take2_ready_operator(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), Actor::Committee) => {
            handle_take2_sent_committee(ctx, *instance_id, *graph_id, content).await
        }
        (GOATMessageContent::Take2Sent(Take2Sent { instance_id, graph_id }), _) => {
            handle_take2_sent_default(ctx, *instance_id, *graph_id).await
        }
        (
            GOATMessageContent::SyncGraphRequest(SyncGraphRequest { instance_id, graph_id }),
            Actor::Committee,
        ) => handle_sync_graph_request(ctx, *instance_id, *graph_id).await,
        (GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph }), _) => {
            handle_sync_graph(ctx, *instance_id, *graph_id, graph).await
        }
        (GOATMessageContent::RequestNodeInfo(node_info), _) => {
            handle_request_node_info(ctx, node_info).await
        }
        (GOATMessageContent::ResponseNodeInfo(node_info), _) => {
            handle_response_node_info(ctx, node_info).await
        }
        _ => Ok(()),
    }
}

fn make_message(ctx: &HandlerContext<'_>, content: &GOATMessageContent) -> GOATMessage {
    GOATMessage::new(ctx.actor.clone(), content.clone())
}

fn build_signed_init_graph(
    instance_id: Uuid,
    graph_id: Uuid,
    operator_keypair: &Keypair,
) -> Result<InitGraph> {
    let operator_peer_id = PeerId::from_str(&get_peer_id())
        .context("decode local operator peer id for InitGraph")?
        .to_bytes();
    Ok(sign_init_graph(instance_id, graph_id, operator_keypair, operator_peer_id))
}

/// A graph-bearing message has two identity representations: its envelope and
/// the signed graph parameters. Never use one to read/write local state while
/// using the other to reconstruct or scan the graph.
fn message_identity_matches(
    message_kind: &str,
    message_instance_id: Uuid,
    message_graph_id: Uuid,
    message_graph_nonce: Option<u64>,
    graph_instance_id: Uuid,
    graph_graph_id: Uuid,
    graph_nonce: u64,
) -> bool {
    let nonce_matches = message_graph_nonce.is_none_or(|nonce| nonce == graph_nonce);
    if message_instance_id == graph_instance_id
        && message_graph_id == graph_graph_id
        && nonce_matches
    {
        return true;
    }

    tracing::warn!(
        "Ignore {message_kind}: message identity {message_instance_id}:{message_graph_id}:{message_graph_nonce:?} does not match graph parameters {graph_instance_id}:{graph_graph_id}:{graph_nonce}"
    );
    false
}

/// Closes a bounded candidate collection window and assigns provisional slots.
/// Final graph slots are assigned only after valid soldering proofs are collected.
fn freeze_operator_candidates(state: &mut OperatorBabeSetupState) -> Result<()> {
    if state.candidate_verifier_pubkeys.is_some() {
        return Ok(());
    }
    if state.candidates.len() < min_required_verifier() {
        bail!(
            "cannot freeze {} verifier candidates before reaching target {}",
            state.candidates.len(),
            min_required_verifier()
        );
    }
    let mut verifier_peer_ids = std::collections::HashSet::new();
    for candidate in &state.candidates {
        if !verifier_peer_ids.insert(&candidate.verifier_peer_id) {
            bail!("cannot freeze duplicate verifier peer id");
        }
    }
    state.candidates.sort_by_key(|candidate| candidate.verifier_pubkey.to_bytes());
    for (candidate_index, candidate) in state.candidates.iter_mut().enumerate() {
        candidate.candidate_index = Some(candidate_index);
        candidate.selected_circuit_indexes =
            derive_finalized_indices(&candidate.setup_package, BABE_M_CC)?;
    }
    state.candidate_verifier_pubkeys =
        Some(state.candidates.iter().map(|candidate| candidate.verifier_pubkey).collect());
    Ok(())
}

fn seal_selected_verifiers(
    state: &mut OperatorBabeSetupState,
    selected_verifier_pubkeys: Vec<PublicKey>,
) -> Result<()> {
    if let Some(existing) = &state.selected_verifier_pubkeys {
        if existing != &selected_verifier_pubkeys {
            bail!("refuse to replace the sealed verifier selection");
        }
        return Ok(());
    }
    if selected_verifier_pubkeys.len() != min_required_verifier() {
        bail!(
            "selected verifier count {} does not match required {}",
            selected_verifier_pubkeys.len(),
            min_required_verifier()
        );
    }
    if selected_verifier_pubkeys.windows(2).any(|pair| pair[0].to_bytes() >= pair[1].to_bytes()) {
        bail!("selected verifier public keys must be unique and canonically ordered");
    }
    if selected_verifier_pubkeys.iter().any(|selected| {
        !state.candidates.iter().any(|candidate| candidate.verifier_pubkey == *selected)
    }) {
        bail!("sealed verifier selection contains a non-candidate public key");
    }
    state.selected_verifier_pubkeys = Some(selected_verifier_pubkeys);
    Ok(())
}

fn selected_gc_data(state: &OperatorBabeSetupState) -> Result<Vec<BitvmGcCircuitData>> {
    let selected = state
        .selected_verifier_pubkeys
        .as_ref()
        .ok_or_else(|| anyhow!("verifier selection is not sealed"))?;
    selected
        .iter()
        .map(|verifier_pubkey| {
            state
                .candidates
                .iter()
                .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
                .and_then(|candidate| candidate.gc_data.clone())
                .ok_or_else(|| {
                    anyhow!("missing verified GC data for sealed verifier {verifier_pubkey}")
                })
        })
        .collect()
}

fn selected_candidate_for_graph_index(
    state: &OperatorBabeSetupState,
    verifier_index: usize,
) -> Result<&OperatorVerifierCandidate> {
    let verifier_pubkey = state
        .selected_verifier_pubkeys
        .as_ref()
        .and_then(|selected| selected.get(verifier_index))
        .ok_or_else(|| anyhow!("missing sealed verifier slot {verifier_index}"))?;
    state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
        .ok_or_else(|| anyhow!("missing candidate for sealed verifier slot {verifier_index}"))
}

/// Stores verified proof data against its immutable candidate slot.
fn record_candidate_gc_data(
    state: &mut OperatorBabeSetupState,
    verifier_pubkey: PublicKey,
    candidate_index: usize,
    setup_package: &CACSetupPackage,
    gc_data: BitvmGcCircuitData,
    prover_state: &BabeProverState,
    soldering_proof_ready: SolderingProofReady,
) -> Result<()> {
    if gc_data.verifier_pubkey != verifier_pubkey {
        bail!("GC slot owner does not match soldering proof verifier");
    }
    let candidate = state
        .candidates
        .iter_mut()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.candidate_index != Some(candidate_index) {
        bail!("candidate index does not match soldering proof slot");
    }
    if candidate.setup_package != *setup_package {
        bail!("soldering proof setup package does not match selected verifier candidate");
    }
    if prover_state.package != *setup_package {
        bail!("BABE prover state setup package does not match selected verifier candidate");
    }
    if candidate.selected_circuit_indexes != prover_state.soldering.finalized_indices {
        bail!("BABE prover state finalized indices do not match selected verifier cut");
    }
    if soldering_proof_ready.candidate_index != candidate_index {
        bail!("soldering proof reference candidate index does not match selected verifier");
    }
    if prover_state.finalized.len() != BABE_M_CC || prover_state.h_msgs.len() != BABE_M_CC {
        bail!("BABE prover state must contain exactly {BABE_M_CC} finalized instances and hashes");
    }
    if prover_state.h_msgs != gc_data.final_msg_hashlocks {
        bail!("BABE prover state hashes do not match GC slot hashes");
    }
    if let Some(existing) = &candidate.gc_data
        && existing != &gc_data
    {
        bail!("conflicting GC data received for verifier candidate");
    }
    if let Some(existing) = &candidate.soldering_proof_ready
        && existing != &soldering_proof_ready
    {
        bail!("conflicting soldering proof reference received for verifier candidate");
    }
    if candidate.gc_data.is_none() {
        candidate.gc_data = Some(gc_data);
    }
    if candidate.soldering_proof_ready.is_none() {
        candidate.soldering_proof_ready = Some(soldering_proof_ready);
    }
    Ok(())
}

fn build_babe_prover_state(
    setup_package: &CACSetupPackage,
    finalized: Vec<FinalizedInstanceData>,
    soldering: SolderingData,
) -> Result<BabeProverState> {
    let h_msgs = finalized
        .iter()
        .map(|finalized| {
            setup_package
                .commits
                .get(finalized.index)
                .map(|commit| commit.h_msg)
                .ok_or_else(|| anyhow!("finalized BABE instance index is out of range"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BabeProverState { package: setup_package.clone(), finalized, soldering, h_msgs })
}

fn validate_verifier_slot_lengths(
    verifier_index: usize,
    gc_data_len: usize,
    verifier_asserts_len: usize,
    disproves_len: usize,
) -> Result<()> {
    if gc_data_len == 0 {
        bail!("graph has no verifier GC slots");
    }
    if gc_data_len != verifier_asserts_len || gc_data_len != disproves_len {
        bail!(
            "graph verifier branch lengths differ: gc_data={gc_data_len}, verifier_asserts={verifier_asserts_len}, disproves={disproves_len}"
        );
    }
    if verifier_index >= gc_data_len {
        bail!("verifier index {verifier_index} out of range for {gc_data_len} slots");
    }
    Ok(())
}

fn validate_verifier_slot(graph: &BitvmGcGraph, verifier_index: usize) -> Result<()> {
    validate_verifier_slot_lengths(
        verifier_index,
        graph.parameters.gc_data.len(),
        graph.verifier_asserts.len(),
        graph.disproves.len(),
    )
}

fn validate_watchtower_branches(graph: &BitvmGcGraph) -> Result<usize> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if watchtower_num == 0 {
        bail!("graph has no watchtower slots");
    }
    if graph.parameters.watchtower_ack_hashlocks.len() != watchtower_num
        || graph.watchtower_challenge_timeouts.len() != watchtower_num
        || graph.operator_challenge_nacks.len() != watchtower_num
    {
        bail!(
            "graph watchtower branch lengths differ: watchtowers={}, ack_hashlocks={}, timeouts={}, nacks={}",
            watchtower_num,
            graph.parameters.watchtower_ack_hashlocks.len(),
            graph.watchtower_challenge_timeouts.len(),
            graph.operator_challenge_nacks.len()
        );
    }
    Ok(watchtower_num)
}

fn find_verifier_index_by_pubkey(
    gc_data: &[BitvmGcCircuitData],
    verifier_pubkey: &PublicKey,
) -> Result<Option<usize>> {
    let matches = gc_data
        .iter()
        .enumerate()
        .filter_map(|(index, data)| (data.verifier_pubkey == *verifier_pubkey).then_some(index))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => bail!("graph contains duplicate slots for verifier {verifier_pubkey}"),
    }
}

fn validate_challenge_witness_index(
    verifier_index: usize,
    challenge_witness: &BabeChallengeAssertWitness,
) -> Result<()> {
    if challenge_witness.verifier_index != verifier_index {
        bail!(
            "challenge witness verifier index {} does not match message verifier index {verifier_index}",
            challenge_witness.verifier_index
        );
    }
    Ok(())
}

fn validate_expected_challenge_assert_txid(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    challenge_assert_txid: Txid,
) -> Result<()> {
    validate_verifier_slot(graph, verifier_index)?;
    let expected_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
    if challenge_assert_txid != expected_txid {
        bail!(
            "challenge assert txid {challenge_assert_txid} does not match graph verifier assert txid {expected_txid}"
        );
    }
    Ok(())
}

/// Resolve the request metadata a `PeginRequest` carries from the canonical
/// `BridgeInRequest` event this node indexed itself.
///
/// The message is gossiped, so its tx hash, height and timestamp are all
/// sender-controlled, and the height alone decides
/// whether the instance ever matches the response-window query in
/// `instance_window_expiration_monitor`. The event watcher already stores the
/// canonical request transaction in `goat_tx_record`, so take all three values
/// from there and never from the message.
///
/// Returns `None` when the event watcher has not indexed the request yet. The
/// current trigger is ignored in that case: once the watcher observes the
/// event, `instance_answers_monitor` creates a canonical local `PeginRequest`.
async fn resolve_pegin_request_metadata(
    local_db: &LocalDB,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<Option<(String, i64, i64)>> {
    let tx_record = {
        let mut storage_processor = local_db.acquire().await?;
        storage_processor
            .find_graph_goat_tx_record(
                &instance_id,
                &Uuid::nil(),
                &GoatTxType::BridgeInRequest.to_string(),
            )
            .await?
    };
    let Some(tx_record) = tx_record else {
        tracing::info!(
            "Ignore PeginRequest for {instance_id}: no local BridgeInRequest event record yet; \
             the event watcher will enqueue the canonical request"
        );
        return Ok(None);
    };
    if tx_record.tx_hash != pegin_request_tx_hash || tx_record.height != pegin_request_height {
        // Not fatal - the canonical record wins either way - but a mismatch is
        // the signature of a forged or stale request, so make it visible.
        tracing::warn!(
            "PeginRequest for {instance_id} claims tx {pegin_request_tx_hash} at height \
             {pegin_request_height}, the indexed BridgeInRequest is tx {} at height {}",
            tx_record.tx_hash,
            tx_record.height
        );
    }
    // The block timestamp comes from the same indexed event; fall back to now
    // rather than to anything the sender supplied.
    let timestamp = tx_record
        .extra
        .as_deref()
        .and_then(|extra| serde_json::from_str::<BridgeInRequestEvent>(extra).ok())
        .and_then(|event| event.block_timestamp.parse::<i64>().ok())
        .unwrap_or_else(current_time_secs);
    Ok(Some((tx_record.tx_hash, tx_record.height, timestamp)))
}

fn should_ignore_invalid_pegin_request(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginRequest(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore PeginRequest for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_invalid_pegin_data(e: &anyhow::Error, instance_id: Uuid) -> bool {
    if let Some(SpecialError::InvalidPeginData(err_msg)) = e.downcast_ref::<SpecialError>() {
        tracing::warn!("Ignore ConfirmInstance for {instance_id}: {err_msg}");
        return true;
    }
    false
}

fn should_ignore_invalid_graph(
    e: &anyhow::Error,
    instance_id: Uuid,
    graph_id: Uuid,
    context: &str,
    from_peer: Option<&PeerId>,
) -> bool {
    if let Some(SpecialError::InvalidGraph(err_msg)) = e.downcast_ref::<SpecialError>() {
        if let Some(peer_id) = from_peer {
            tracing::warn!(
                "Ignore {context} for {instance_id}:{graph_id} from {}: {err_msg}",
                peer_id.to_string()
            );
        } else {
            tracing::warn!("Ignore {context} for {instance_id}:{graph_id}: {err_msg}");
        }
        return true;
    }
    false
}

fn should_ignore_committee_error(
    e: &anyhow::Error,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    ctx: &HandlerContext<'_>,
    context: &str,
) -> bool {
    let peer = ctx.from_peer_id.to_string();
    match e.downcast_ref::<SpecialError>() {
        Some(SpecialError::InvalidCommittee(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: {err_msg}"
                );
            } else {
                tracing::warn!("Ignore {context} for {instance_id} from {peer}: {err_msg}");
            }
            true
        }
        Some(SpecialError::EvmReverted(err_msg)) => {
            if let Some(graph_id) = graph_id {
                tracing::warn!(
                    "Ignore {context} for {instance_id}:{graph_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            } else {
                tracing::warn!(
                    "Ignore {context} for {instance_id} from {peer}: fail to validate committee info on chain: {err_msg}"
                );
            }
            true
        }
        _ => false,
    }
}

async fn ensure_self_or_valid_committee(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    received_committee_pubkey: &PublicKey,
    context: &str,
) -> Result<bool> {
    if ctx.is_self_peer {
        return Ok(true);
    }
    if let Err(e) = validate_committee(
        ctx.goat_client,
        &ctx.from_peer_id,
        instance_id,
        received_committee_pubkey,
    )
    .await
    {
        if should_ignore_committee_error(&e, instance_id, graph_id, ctx, context) {
            return Ok(false);
        }
        bail!(e);
    }
    Ok(true)
}

async fn ensure_self_or_valid_committee_with_evm(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Option<Uuid>,
    received_committee_pubkey: &PublicKey,
    committee_evm_address: &alloy::primitives::Address,
    context: &str,
) -> Result<bool> {
    if ctx.is_self_peer {
        return Ok(true);
    }
    if let Err(e) = validate_committee_with_evm_address(
        ctx.goat_client,
        &ctx.from_peer_id,
        instance_id,
        received_committee_pubkey,
        committee_evm_address,
    )
    .await
    {
        if should_ignore_committee_error(&e, instance_id, graph_id, ctx, context) {
            return Ok(false);
        }
        bail!(e);
    }
    Ok(true)
}

async fn refresh_and_compensate(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
    compensation_anchor_status: GraphStatus,
) -> Result<(GraphStatus, Option<ChallengeSubStatus>, bool)> {
    let refresh =
        refresh_graph(ctx.local_db, ctx.btc_client, ctx.goat_client, instance_id, graph_id, graph)
            .await?;
    let graph_status = refresh.status;
    let sub_status = refresh.sub_status;
    tracing::info!("Graph {graph_id} latest status: {graph_status}");
    if refresh.status_transition_accepted {
        compensate_graph_events(
            ctx.local_db,
            ctx.btc_client,
            instance_id,
            graph_id,
            graph,
            refresh.scan.as_ref(),
            compensation_anchor_status,
            graph_status,
        )
        .await?;
    }
    Ok((graph_status, sub_status, refresh.status_transition_accepted))
}

async fn refresh_newly_finalized_graph(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
) -> Result<()> {
    // Reconcile every verified GraphFinalize, including a duplicate. A prior
    // attempt may have stored the finalized definition but failed before its
    // first chain scan completed.
    refresh_and_compensate(ctx, instance_id, graph_id, graph, GraphStatus::CommitteePresigned)
        .await?;
    Ok(())
}

async fn get_graph_for_refresh(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<BitvmGcGraph> {
    let graph = get_graph(ctx.local_db, instance_id, graph_id)
        .await?
        .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
    BitvmGcGraph::from_simplified(&graph)
}

async fn get_graph_for_refresh_or_defer(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: &GOATMessage,
) -> Result<Option<BitvmGcGraph>> {
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(None),
    };
    Ok(Some(BitvmGcGraph::from_simplified(&graph)?))
}

async fn refresh_graph_status(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    message: Option<&GOATMessage>,
    compensate_from_status: GraphStatus,
) -> Result<Option<(BitvmGcGraph, GraphStatus, Option<ChallengeSubStatus>)>> {
    let graph = match message {
        Some(message) => {
            match get_graph_for_refresh_or_defer(ctx, instance_id, graph_id, message).await? {
                Some(v) => v,
                None => return Ok(None),
            }
        }
        None => get_graph_for_refresh(ctx, instance_id, graph_id).await?,
    };
    let (graph_status, sub_status, status_transition_accepted) =
        refresh_and_compensate(ctx, instance_id, graph_id, &graph, compensate_from_status).await?;
    if !status_transition_accepted {
        tracing::warn!(
            "Ignore graph action for {instance_id}:{graph_id}: chain scan status was rejected or graph is missing"
        );
        return Ok(None);
    }
    Ok(Some((graph, graph_status, sub_status)))
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. bind the request metadata to the event this node indexed itself
    let Some((pegin_request_tx_hash, pegin_request_height, pegin_timestamp)) =
        resolve_pegin_request_metadata(
            ctx.local_db,
            instance_id,
            pegin_request_tx_hash,
            pegin_request_height,
        )
        .await?
    else {
        return Ok(());
    };
    // 2. read & check the pegin request data
    let (user_info, pegin_amount, answered_by) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };

    // 3. save the pegin request data to local db
    let stored = store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash,
            pegin_request_height,
            pegin_timestamp,
        },
    )
    .await?;
    if !stored {
        // The instance has already moved on, so answering now would be a
        // duplicate on-chain call for a request this node handled long ago.
        return Ok(());
    }
    // 4. call Gateway.answerPeginRequest
    //
    // PeginRequest is gossiped and re-deliverable, and the pegin data stays
    // Pending while answers accumulate, so nothing above notices a replay.
    // Gateway.answerPeginRequest does not reject a repeat answer either - it
    // overwrites the stored pubkey and re-emits CommitteeResponse - so without
    // this every re-delivery spends another transaction. The contract keys
    // answers on msg.sender, so compare against the signer that sends it.
    if answered_by.contains(&ctx.goat_client.get_default_signer_address()) {
        tracing::info!(
            "Skip answerPeginRequest for {instance_id}: this committee already answered"
        );
        return Ok(());
    }
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair =
        load_or_create_committee_instance_keypair(&committee_master_key, instance_id)?;
    let pubkey_for_instance = instance_keypair.public_key().into();
    ctx.goat_client.gateway_answer_pegin_request(&instance_id, &pubkey_for_instance).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_request_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    pegin_request_tx_hash: &str,
    pegin_request_height: i64,
) -> Result<()> {
    // triggered by BridgeInRequest event
    // 1. bind the request metadata to the event this node indexed itself
    let Some((pegin_request_tx_hash, pegin_request_height, pegin_timestamp)) =
        resolve_pegin_request_metadata(
            ctx.local_db,
            instance_id,
            pegin_request_tx_hash,
            pegin_request_height,
        )
        .await?
    else {
        return Ok(());
    };
    // 2. read & check the pegin request data
    let (user_info, pegin_amount, _) =
        match read_pegin_request(ctx.btc_client, ctx.goat_client, instance_id).await {
            Ok(v) => v,
            Err(e) => {
                if should_ignore_invalid_pegin_request(&e, instance_id) {
                    return Ok(());
                }
                bail!(e)
            }
        };
    // 3. save the pegin request data to local db
    store_pegin_request(
        ctx.btc_client,
        ctx.local_db,
        GenerateInstanceParams {
            instance_id,
            user_info,
            pegin_amount,
            pegin_request_tx_hash,
            pegin_request_height,
            pegin_timestamp,
        },
    )
    .await?;
    Ok(())
}

async fn defer_confirm_instance_until_previous_graph_presigned(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    successor_nonce: u64,
    operator_pubkey: &PublicKey,
) -> Result<bool> {
    if successor_nonce == 0 {
        return Ok(false);
    }

    let previous_nonce = successor_nonce - 1;
    let retry_message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::ConfirmInstance(ConfirmInstance { instance_id }),
    );
    let Some((previous_instance_id, previous_graph_id)) =
        get_graph_id_by_nonce(ctx.local_db, previous_nonce, operator_pubkey).await?
    else {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &retry_message,
            60,
            MessageDeferReason::PreviousGraphPending,
            "previous graph nonce is not available locally",
        )
        .await?;
        tracing::warn!(
            "Defer ConfirmInstance for {instance_id}: previous graph with nonce {previous_nonce} is not available locally"
        );
        return Ok(true);
    };
    let Some(previous_graph) =
        get_graph(ctx.local_db, previous_instance_id, previous_graph_id).await?
    else {
        if let Err(error) = try_send_sync_graph_request(
            ctx.swarm,
            ctx.goat_client,
            previous_instance_id,
            previous_graph_id,
        )
        .await
        {
            tracing::warn!(
                "Failed to send SyncGraphRequest for previous graph {previous_instance_id}:{previous_graph_id}: {error}"
            );
        }
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &retry_message,
            60,
            MessageDeferReason::PreviousGraphPending,
            "previous graph definition is not available locally",
        )
        .await?;
        tracing::info!(
            "Defer ConfirmInstance for {instance_id}: waiting for previous graph raw data {previous_instance_id}:{previous_graph_id}"
        );
        return Ok(true);
    };
    if previous_graph.committee_pre_signed() {
        return Ok(false);
    }

    push_local_unhandled_messages_with_reason(
        ctx.local_db,
        instance_id,
        &retry_message,
        60,
        MessageDeferReason::PreviousGraphPending,
        "previous graph is waiting for committee pre-signatures",
    )
    .await?;
    let message_content = GOATMessageContent::CreateGraph(CreateGraph {
        instance_id: previous_instance_id,
        graph_id: previous_graph_id,
        graph_nonce: previous_graph.parameters.graph_nonce,
        graph: previous_graph,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    tracing::info!(
        "Defer ConfirmInstance for {instance_id}: re-broadcast previous CreateGraph {previous_instance_id}:{previous_graph_id} until it is committee pre-signed"
    );
    Ok(true)
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // triggered by PeginDeposit tx
    // 0. check if graph already created
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if let Some(graph) = get_graph_by_instance_id_and_operator_pubkey(
        ctx.local_db,
        instance_id,
        &local_operator_pubkey,
    )
    .await?
    {
        if defer_confirm_instance_until_previous_graph_presigned(
            ctx,
            instance_id,
            graph.parameters.graph_nonce,
            &local_operator_pubkey,
        )
        .await?
        {
            return Ok(());
        }
        let graph_id = graph.parameters.graph_id;
        tracing::info!("Graph already created for {instance_id}, graph_id: {}", graph_id);
        let message_content = GOATMessageContent::CreateGraph(CreateGraph {
            instance_id,
            graph_id,
            graph_nonce: graph.parameters.graph_nonce,
            graph,
        });
        let msg = GOATMessage::new(Actor::All, message_content);
        send_to_peer(ctx.swarm, msg).await?;
        return Ok(());
    }

    let pending_graph_id = {
        let mut storage = ctx.local_db.acquire().await?;
        storage
            .find_pending_graph_init_by_instance_and_operator_pubkey(
                &instance_id,
                &local_operator_pubkey.to_string(),
            )
            .await?
            .map(|pending| pending.graph_id)
    };
    if let Some(graph_id) = pending_graph_id {
        if let Some((next_graph_nonce, _)) =
            get_current_prekickoff_tx(ctx.local_db, &local_operator_pubkey).await?
            && defer_confirm_instance_until_previous_graph_presigned(
                ctx,
                instance_id,
                next_graph_nonce,
                &local_operator_pubkey,
            )
            .await?
        {
            return Ok(());
        }
        tracing::info!("Resume pending graph setup for {instance_id}, graph_id: {graph_id}");
        let message_content = GOATMessageContent::InitGraph(build_signed_init_graph(
            instance_id,
            graph_id,
            &operator_master_key.master_keypair(),
        )?);
        enqueue_graph_setup_outbox_message(
            ctx.local_db,
            GOATMessage::new(Actor::Verifier, message_content),
            None,
        )
        .await?;

        return Ok(());
    }

    // 1. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        bail!("Invalid ConfirmInstance: pegin deposit tx {pegin_deposit_txid} not found on chain");
    }

    if let Some((next_graph_nonce, _)) =
        get_current_prekickoff_tx(ctx.local_db, &local_operator_pubkey).await?
        && defer_confirm_instance_until_previous_graph_presigned(
            ctx,
            instance_id,
            next_graph_nonce,
            &local_operator_pubkey,
        )
        .await?
    {
        return Ok(());
    }
    // after PeginPrepare is confirmed, broadcast InitGraph and let Verifiers generate GC.

    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    let graph_id = Uuid::new_v4();
    let mut storage = ctx.local_db.acquire().await?;
    storage
        .upsert_pending_graph_init(&instance_id, &local_operator_pubkey.to_string(), &graph_id)
        .await?;
    let message_content = GOATMessageContent::InitGraph(build_signed_init_graph(
        instance_id,
        graph_id,
        &operator_master_key.master_keypair(),
    )?);
    enqueue_graph_setup_outbox_message(
        ctx.local_db,
        GOATMessage::new(Actor::Verifier, message_content),
        None,
    )
    .await?;

    Ok(())
}

// Generate garbled circuits and enqueue GenCircuits without blocking the swarm.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %message.instance_id, graph_id = %message.graph_id))]
async fn handle_init_graph_verifier(context: &HeavyTaskContext, message: InitGraph) -> Result<()> {
    let InitGraph { instance_id, graph_id, operator_pubkey, operator_peer_id, .. } = &message;
    if operator_peer_id != &context.from_peer_id.to_bytes() {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            from_peer_id = %context.from_peer_id,
            "Ignore InitGraph whose signed operator peer id differs from its P2P source"
        );
        return Ok(());
    }
    if !verify_init_graph_signature(&message) {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            operator_pubkey = %operator_pubkey,
            "Ignore InitGraph with invalid operator signature"
        );
        return Ok(());
    }
    if let Err(error) = validate_operator_stake(&context.goat_client, operator_pubkey).await {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            operator_pubkey = %operator_pubkey,
            error = %error,
            "Ignore InitGraph from an operator that does not meet stake requirements"
        );
        return Ok(());
    }

    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();

    let saved_verifier_state = load_babe_setup_state(&context.local_db, *instance_id, *graph_id)?
        .and_then(|state| state.verifier)
        .filter(|state| state.verifier_pubkey == verifier_pubkey);
    let verifier_state = if let Some(saved) = saved_verifier_state {
        if saved.operator_pubkey != *operator_pubkey || saved.operator_peer_id != *operator_peer_id
        {
            tracing::warn!(
                instance_id = %instance_id,
                graph_id = %graph_id,
                expected_operator_peer = %PeerId::from_bytes(&saved.operator_peer_id)
                    .map(|peer_id| peer_id.to_string())
                    .unwrap_or_else(|_| "invalid".to_owned()),
                from_peer_id = %context.from_peer_id,
                "Ignore InitGraph with a different authenticated operator identity for an existing verifier setup"
            );
            return Ok(());
        }
        saved
    } else {
        get_babe_gc_asset_paths()?;
        let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE setup")?;
        let static_input = derive_operator_static_input()?;
        let (setup_package, private_state) = tokio::task::spawn_blocking(move || {
            build_real_setup_package(BABE_N_CC, &vk, static_input)
        })
        .await
        .context("real BABE setup task failed")??;
        tracing::info!("Verifier setup done.");
        VerifierBabeSetupState {
            verifier_pubkey,
            operator_pubkey: *operator_pubkey,
            operator_peer_id: operator_peer_id.clone(),
            setup_package,
            private_state,
            finalized_indices: vec![],
            soldering_proof_ready: None,
        }
    };

    let setup_package = verifier_state.setup_package.clone();
    let operator_peer_id = PeerId::from_bytes(&verifier_state.operator_peer_id)
        .map(|peer_id| peer_id.to_string())
        .context("decode operator peer id saved from InitGraph")?;
    update_babe_setup_state(&context.local_db, *instance_id, *graph_id, |state| {
        state.verifier = Some(verifier_state);
    })?;

    let gen_circuits = GenCircuits {
        instance_id: *instance_id,
        graph_id: *graph_id,
        verifier_pubkey,
        setup_package,
    };
    let message = GOATMessage::new(Actor::Operator, GOATMessageContent::GenCircuits(gen_circuits));
    let outbox_id =
        enqueue_graph_setup_outbox_message(&context.local_db, message, Some(&operator_peer_id))
            .await?;
    tracing::info!(
        event = "verifier_gc_setup",
        outcome = "enqueued",
        outbox_id,
        "enqueued GenCircuits for swarm publication"
    );

    Ok(())
}

//  select a subset of GC and broadcast CutCircuits.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_gen_circuits_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: &PublicKey,
    setup_package: &CACSetupPackage,
) -> Result<()> {
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: no local pending graph session"
        );
        return Ok(());
    }

    if setup_package.commits.len() != BABE_N_CC {
        bail!(
            "invalid GenCircuits setup package commitment count: expected {BABE_N_CC}, got {}",
            setup_package.commits.len()
        );
    }

    let verifier_peer_id = ctx.from_peer_id.to_bytes();
    if !ctx.goat_client.committee_mana_is_verifier(&verifier_peer_id).await.with_context(|| {
        format!(
            "failed to validate GenCircuits sender {} against the verifier registry",
            ctx.from_peer_id
        )
    })? {
        tracing::warn!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: sender {} is not a registered verifier",
            ctx.from_peer_id
        );
        return Ok(());
    }

    let mut state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?.unwrap_or_default();
    let operator_state = state.operator.get_or_insert_with(|| OperatorBabeSetupState {
        candidate_verifier_pubkeys: None,
        candidates: vec![],
        candidate_collection_started_at: None,
        proof_collection_started_at: None,
        selected_verifier_pubkeys: None,
        asserted_operator_proof: None,
    });

    let was_frozen = operator_state.candidate_verifier_pubkeys.is_some();
    if let Some(existing) = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_peer_id == verifier_peer_id)
    {
        if existing.verifier_pubkey != *verifier_pubkey {
            tracing::warn!(
                "Ignore GenCircuits for {instance_id}:{graph_id}: verifier peer {} already submitted a different public key",
                ctx.from_peer_id
            );
            return Ok(());
        }
        if existing.setup_package != *setup_package {
            bail!("conflicting GenCircuits setup package for verifier {verifier_pubkey}");
        }
    } else if operator_state
        .candidates
        .iter()
        .any(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
    {
        tracing::warn!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: verifier public key {verifier_pubkey} is already bound to another peer"
        );
        return Ok(());
    } else if was_frozen {
        tracing::debug!(
            "Ignore GenCircuits for {instance_id}:{graph_id}: verifier membership is frozen"
        );

        return Ok(());
    } else {
        if operator_state.candidates.len()
            >= min_required_verifier().saturating_add(get_verifier_candidate_backup_count())
        {
            tracing::debug!(
                "Ignore GenCircuits for {instance_id}:{graph_id}: candidate collection reached its configured limit"
            );
            return Ok(());
        }
        operator_state.candidates.push(OperatorVerifierCandidate {
            verifier_peer_id,
            verifier_pubkey: *verifier_pubkey,
            setup_package: setup_package.clone(),
            candidate_index: None,
            selected_circuit_indexes: vec![],
            gc_data: None,
            soldering_proof_ready: None,
        });
        operator_state.candidate_collection_started_at.get_or_insert_with(current_time_secs);
    }

    if operator_state.candidate_verifier_pubkeys.is_none() {
        let started_at =
            operator_state.candidate_collection_started_at.get_or_insert_with(current_time_secs);
        let elapsed = current_time_secs() - *started_at;
        let window = get_verifier_candidate_collection_window_secs();
        let reached_limit = operator_state.candidates.len()
            >= min_required_verifier().saturating_add(get_verifier_candidate_backup_count());
        if operator_state.candidates.len() < min_required_verifier()
            || (!reached_limit && elapsed < window)
        {
            let retry_after_secs = (window - elapsed).max(1);
            let candidate_count = operator_state.candidates.len();
            save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;
            return Err(retryable_dispatch_error(
                RetryableDispatchReason::DependencyPending,
                Some(retry_after_secs),
                format!(
                    "collecting verifier candidates: {}/{} received",
                    candidate_count,
                    min_required_verifier(),
                ),
            ));
        }
    }

    if operator_state.candidate_verifier_pubkeys.is_none() {
        freeze_operator_candidates(operator_state)?;
    }
    let cut_candidates = if was_frozen { Vec::new() } else { operator_state.candidates.clone() };

    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &state)?;
    for candidate in cut_candidates {
        let message = GOATMessage::new(
            Actor::Verifier,
            GOATMessageContent::CutCircuits(CutCircuits {
                instance_id,
                graph_id,
                verifier_pubkey: candidate.verifier_pubkey,
                candidate_index: candidate
                    .candidate_index
                    .expect("candidate slot assigned before CutCircuits"),
                selected_circuit_indexes: candidate.selected_circuit_indexes,
            }),
        );
        let ack_peer_id =
            PeerId::from_bytes(&candidate.verifier_peer_id).map(|peer_id| peer_id.to_string()).ok();
        enqueue_graph_setup_outbox_message(ctx.local_db, message, ack_peer_id.as_deref()).await?;
    }
    Ok(())
}

// Generate proofs for the chosen GC and enqueue SolderingProofReady.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_cut_circuits_verifier(
    context: &HeavyTaskContext,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: &PublicKey,
    candidate_index: usize,
    selected_circuit_indexes: &Vec<usize>,
) -> Result<()> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if &local_verifier_pubkey != verifier_pubkey {
        tracing::debug!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: target verifier pubkey does not match local verifier"
        );

        return Ok(());
    }

    let Some(mut verifier_state) = load_babe_setup_state(&context.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        tracing::warn!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: missing BABE verifier setup state"
        );
        return Ok(());
    };

    if verifier_state.verifier_pubkey != *verifier_pubkey {
        tracing::warn!(
            "Ignore CutCircuits for {instance_id}:{graph_id}: verifier pubkey does not match saved BABE setup state"
        );

        return Ok(());
    }
    if verifier_state.operator_peer_id != context.from_peer_id.to_bytes() {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            from_peer_id = %context.from_peer_id,
            "Ignore CutCircuits from a peer other than the operator that initiated verifier setup"
        );
        return Ok(());
    }

    if let Some(soldering_proof_ready) = verifier_state.soldering_proof_ready.clone() {
        if soldering_proof_ready.candidate_index != candidate_index {
            bail!(
                "CutCircuits candidate index {candidate_index} conflicts with persisted slot {}",
                soldering_proof_ready.candidate_index
            );
        }
        if verifier_state.finalized_indices != *selected_circuit_indexes {
            bail!("CutCircuits finalized indices conflict with persisted selection");
        }
        let message = GOATMessage::new(
            Actor::Operator,
            GOATMessageContent::SolderingProofReady(soldering_proof_ready),
        );
        let operator_peer_id = PeerId::from_bytes(&verifier_state.operator_peer_id)
            .map(|peer_id| peer_id.to_string())
            .context("decode operator peer id saved from InitGraph")?;
        let outbox_id =
            enqueue_graph_setup_outbox_message(&context.local_db, message, Some(&operator_peer_id))
                .await?;
        tracing::info!(
            event = "verifier_soldering_proof",
            outcome = "enqueued",
            outbox_id,
            "enqueued SolderingProofReady for swarm publication"
        );

        return Ok(());
    }

    let setup_package = verifier_state.setup_package.clone();
    get_babe_gc_asset_paths()?;

    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE opening")?;
    let static_input = derive_operator_static_input()?;
    let private_state = verifier_state.private_state.clone();
    let selected_indices = selected_circuit_indexes.clone();
    let package_for_opening = setup_package.clone();
    let soldering_builder = Arc::clone(
        context
            .soldering_builder
            .as_ref()
            .context("BABE soldering builder is not initialized for Verifier")?,
    );
    let (opened, finalized, soldering) = tokio::task::spawn_blocking(move || {
        open_real_setup_and_solder(
            &soldering_builder,
            &private_state,
            &package_for_opening,
            &selected_indices,
            &vk,
            static_input,
        )
    })
    .await
    .context("real BABE opening task failed")??;

    let soldering_proof_ready = save_soldering_proof_payload(
        instance_id,
        graph_id,
        candidate_index,
        &opened,
        &finalized,
        &soldering,
    )
    .await?;
    verifier_state.finalized_indices = selected_circuit_indexes.clone();
    verifier_state.soldering_proof_ready = Some(soldering_proof_ready.clone());

    let operator_peer_id = PeerId::from_bytes(&verifier_state.operator_peer_id)
        .map(|peer_id| peer_id.to_string())
        .context("decode operator peer id saved from InitGraph")?;
    update_babe_setup_state(&context.local_db, instance_id, graph_id, |state| {
        state.verifier = Some(verifier_state);
    })?;

    let message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::SolderingProofReady(soldering_proof_ready),
    );
    let outbox_id =
        enqueue_graph_setup_outbox_message(&context.local_db, message, Some(&operator_peer_id))
            .await?;
    tracing::info!(
        event = "verifier_soldering_proof",
        outcome = "enqueued",
        outbox_id,
        "enqueued SolderingProofReady for swarm publication"
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_soldering_proof_ready_operator(
    context: &HeavyTaskContext,
    instance_id: Uuid,
    graph_id: Uuid,
    candidate_index: usize,
    payload_hash: [u8; 32],
    total_len: usize,
) -> Result<()> {
    if total_len == 0 {
        bail!("SolderingProofReady total_len must be greater than zero");
    }
    let soldering_proof_ready =
        SolderingProofReady { instance_id, graph_id, candidate_index, payload_hash, total_len };
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        &context.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore SolderingProofReady for {instance_id}:{graph_id}: no local pending graph session"
        );

        return Ok(());
    }

    let state =
        load_babe_setup_state(&context.local_db, instance_id, graph_id)?.ok_or_else(|| {
            retryable_dispatch_error(
                RetryableDispatchReason::DependencyPending,
                Some(30),
                format!("missing BABE setup state for pending graph {graph_id}"),
            )
        })?;
    let operator_state = state.operator.as_ref().ok_or_else(|| {
        retryable_dispatch_error(
            RetryableDispatchReason::DependencyPending,
            Some(30),
            format!("missing operator BABE setup state for pending graph {graph_id}"),
        )
    })?;
    let frozen = operator_state.candidate_verifier_pubkeys.as_ref().ok_or_else(|| {
        retryable_dispatch_error(
            RetryableDispatchReason::DependencyPending,
            Some(30),
            "operator verifier membership is not frozen",
        )
    })?;
    let verifier_pubkey = frozen.get(candidate_index).ok_or_else(|| {
        anyhow!("SolderingProofReady candidate index {candidate_index} out of range")
    })?;
    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == *verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.candidate_index != Some(candidate_index) {
        bail!("selected verifier candidate index does not match SolderingProofReady slot");
    }
    if operator_state.selected_verifier_pubkeys.as_ref().is_some_and(|selected| {
        !selected.iter().any(|selected_pubkey| selected_pubkey == verifier_pubkey)
    }) {
        tracing::info!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            candidate_index,
            verifier_pubkey = %verifier_pubkey,
            "Ignore late SolderingProofReady from verifier outside the sealed graph selection"
        );
        return Ok(());
    }
    let verifier_peer_id = context.from_peer_id.to_bytes();
    if candidate.verifier_peer_id != verifier_peer_id {
        tracing::warn!(
            "Ignore SolderingProofReady for {instance_id}:{graph_id}: sender {} does not own verifier candidate {candidate_index}",
            context.from_peer_id
        );
        return Ok(());
    }

    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        candidate_index,
        &payload_hash,
    )?;
    tracing::info!(
        from_peer_id = %context.from_peer_id,
        instance_id = %instance_id,
        graph_id = %graph_id,
        candidate_index,
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "received SolderingProofReady; reading payload from store"
    );
    let payload = match read_soldering_proof_store_payload(&payload_path).await {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(
                instance_id = %instance_id,
                graph_id = %graph_id,
                candidate_index,
                payload_path = %payload_path,
                error = %err,
                "failed to read soldering proof payload from store"
            );
            return Err(retryable_dispatch_error(
                RetryableDispatchReason::PayloadNotReady,
                Some(30),
                format!("read soldering proof payload from store: {err}"),
            ));
        }
    };
    tracing::info!(
        instance_id = %instance_id,
        graph_id = %graph_id,
        candidate_index,
        bytes = payload.len(),
        total_len,
        payload_hash = %soldering_payload_hash_hex(&payload_hash),
        payload_path = %payload_path,
        "read soldering proof payload from store, start processing"
    );
    let result =
        handle_soldering_proof_payload_operator(context, &soldering_proof_ready, &payload).await;
    context.metrics_state.record_pegin_graph_setup(result.is_ok());
    result
}

fn decode_soldering_proof_payload(
    soldering_proof_ready: &SolderingProofReady,
    payload: &[u8],
) -> Result<CompactSolderingProofPayload> {
    let SolderingProofReady { instance_id, graph_id, candidate_index, payload_hash, total_len } =
        soldering_proof_ready;
    if payload.len() != *total_len {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            candidate_index,
            actual_len = payload.len(),
            total_len,
            payload_hash = %soldering_payload_hash_hex(payload_hash),
            "SolderingProof payload length mismatch"
        );
        bail!(
            "SolderingProof payload length {} does not match total_len {total_len}",
            payload.len()
        );
    }
    let actual_hash = soldering_payload_hash(payload);
    if actual_hash != *payload_hash {
        tracing::warn!(
            instance_id = %instance_id,
            graph_id = %graph_id,
            candidate_index,
            expected_hash = %soldering_payload_hash_hex(payload_hash),
            actual_hash = %soldering_payload_hash_hex(&actual_hash),
            "SolderingProof payload hash mismatch"
        );
        bail!("SolderingProof payload hash mismatch");
    }
    bincode::deserialize(payload).context("deserialize compact soldering proof payload")
}

pub(crate) async fn handle_soldering_proof_payload_operator(
    context: &HeavyTaskContext,
    soldering_proof_ready: &SolderingProofReady,
    payload: &[u8],
) -> Result<()> {
    let decode_started_at = Instant::now();
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "payload_decode",
        outcome = "started",
        candidate_index = soldering_proof_ready.candidate_index,
        payload_len = payload.len(),
        "decoding soldering proof payload"
    );
    let payload = decode_soldering_proof_payload(soldering_proof_ready, payload)?;
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "payload_decode",
        outcome = "completed",
        candidate_index = soldering_proof_ready.candidate_index,
        elapsed_ms = decode_started_at.elapsed().as_millis(),
        "decoded soldering proof payload"
    );
    handle_compact_soldering_proof_operator(context, soldering_proof_ready, payload).await
}

// verify Verifier SolderingProof, build Graph and broadcast CreateGraph.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %soldering_proof_ready.instance_id, graph_id = %soldering_proof_ready.graph_id))]
async fn handle_compact_soldering_proof_operator(
    context: &HeavyTaskContext,
    soldering_proof_ready: &SolderingProofReady,
    payload: CompactSolderingProofPayload,
) -> Result<()> {
    let instance_id = soldering_proof_ready.instance_id;
    let graph_id = soldering_proof_ready.graph_id;
    let candidate_index = soldering_proof_ready.candidate_index;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let local_operator_pubkey = operator_master_key.master_keypair().public_key().into();
    if !pending_graph_belongs_to_operator(
        &context.local_db,
        instance_id,
        graph_id,
        &local_operator_pubkey,
    )
    .await?
    {
        tracing::debug!(
            "Ignore SolderingProof for {instance_id}:{graph_id}: no local pending graph session"
        );

        return Ok(());
    }

    let mut state =
        load_babe_setup_state(&context.local_db, instance_id, graph_id)?.ok_or_else(|| {
            retryable_dispatch_error(
                RetryableDispatchReason::DependencyPending,
                Some(30),
                format!("missing BABE setup state for pending graph {graph_id}"),
            )
        })?;
    let operator_state = state.operator.as_mut().ok_or_else(|| {
        retryable_dispatch_error(
            RetryableDispatchReason::DependencyPending,
            Some(30),
            format!("missing operator BABE setup state for pending graph {graph_id}"),
        )
    })?;
    let frozen = operator_state.candidate_verifier_pubkeys.as_ref().ok_or_else(|| {
        retryable_dispatch_error(
            RetryableDispatchReason::DependencyPending,
            Some(30),
            "operator verifier membership is not frozen",
        )
    })?;
    let verifier_pubkey = *frozen
        .get(candidate_index)
        .ok_or_else(|| anyhow!("SolderingProof candidate index {candidate_index} out of range"))?;

    let candidate = operator_state
        .candidates
        .iter()
        .find(|candidate| candidate.verifier_pubkey == verifier_pubkey)
        .ok_or_else(|| anyhow!("selected verifier candidate is missing"))?;
    if candidate.candidate_index != Some(candidate_index) {
        bail!("selected verifier candidate index does not match SolderingProof slot");
    }
    let setup_package = candidate.setup_package.clone();
    let claimed_finalized_indices = candidate.selected_circuit_indexes.clone();
    let expand_started_at = Instant::now();
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "payload_expand",
        outcome = "started",
        candidate_index,
        "expanding compact soldering proof"
    );
    let (opened, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand compact soldering proof payload")?;
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "payload_expand",
        outcome = "completed",
        candidate_index,
        opened_instances = opened.len(),
        finalized_instances = finalized.len(),
        elapsed_ms = expand_started_at.elapsed().as_millis(),
        "expanded compact soldering proof"
    );

    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for BABE validation")?;
    let static_input = derive_operator_static_input()?;
    let package_for_validation = setup_package.clone();
    let opened_for_validation = opened.clone();
    let finalized_for_validation = finalized.clone();
    let soldering_for_validation = soldering.clone();
    let soldering_builder = Arc::clone(
        context
            .soldering_builder
            .as_ref()
            .context("BABE soldering builder is not initialized for Operator")?,
    );

    let verification_started_at = Instant::now();
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "setup_verify",
        outcome = "started",
        candidate_index,
        opened_instances = opened.len(),
        finalized_instances = finalized.len(),
        "verifying verifier soldering proof"
    );
    tokio::task::spawn_blocking(move || {
        verify_real_setup(
            &soldering_builder,
            &package_for_validation,
            &opened_for_validation,
            &finalized_for_validation,
            &soldering_for_validation,
            &vk,
            &claimed_finalized_indices,
            static_input,
        )
    })
    .await
    .context("real BABE setup verification task failed")??;
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "setup_verify",
        outcome = "completed",
        candidate_index,
        elapsed_ms = verification_started_at.elapsed().as_millis(),
        "verified verifier soldering proof"
    );

    tracing::info!(
        event = "operator_graph_creation",
        outcome = "soldering_verified",
        candidate_index,
        verifier_pubkey = %verifier_pubkey,
        finalized_instances = finalized.len(),
        payload_hash = %hex::encode(soldering_proof_ready.payload_hash),
        "verified verifier soldering proof"
    );

    if finalized.len() != BABE_M_CC {
        bail!("each verifier must contribute exactly {BABE_M_CC} finalized BABE instances");
    }
    let epk = &setup_package.commits[finalized[0].index].epk;
    let gc_data_started_at = Instant::now();
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "gc_data_extract",
        outcome = "started",
        candidate_index,
        "building BABE prover state and extracting GC data"
    );
    let prover_state = build_babe_prover_state(&setup_package, finalized, soldering)?;
    let gc_data = extract_gc_circuit_data(verifier_pubkey, epk, &prover_state.h_msgs)?;
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "gc_data_extract",
        outcome = "completed",
        candidate_index,
        elapsed_ms = gc_data_started_at.elapsed().as_millis(),
        "extracted GC data from soldering proof"
    );
    record_candidate_gc_data(
        operator_state,
        verifier_pubkey,
        candidate_index,
        &setup_package,
        gc_data,
        &prover_state,
        soldering_proof_ready.clone(),
    )?;
    let completed_slots =
        operator_state.candidates.iter().filter(|candidate| candidate.gc_data.is_some()).count();
    let required_slots = min_required_verifier();
    let proof_window_started_at =
        operator_state.proof_collection_started_at.get_or_insert_with(current_time_secs);
    let elapsed = current_time_secs() - *proof_window_started_at;
    let collection_window = get_verifier_candidate_collection_window_secs();
    if completed_slots < required_slots || elapsed < collection_window {
        if let Err(error) = save_babe_setup_state(&context.local_db, instance_id, graph_id, &state)
        {
            tracing::error!(
                event = "operator_graph_creation",
                outcome = "failed",
                stage = "babe_state_persist",
                candidate_index,
                error = %error,
                "failed to persist incomplete operator BABE setup state"
            );
            return Err(error).context("persist incomplete operator BABE setup state");
        }
        tracing::info!(
            event = "operator_graph_creation",
            outcome = "waiting_for_soldering",
            candidate_index,
            completed_slots,
            required_slots,
            retry_after_secs = (collection_window - elapsed).max(1),
            "persisted verified soldering proof; waiting for the proof selection window"
        );
        return Err(retryable_dispatch_error(
            RetryableDispatchReason::DependencyPending,
            Some((collection_window - elapsed).max(1)),
            format!("collecting verified soldering proofs: {completed_slots}/{required_slots}"),
        ));
    }

    let selected_verifier_pubkeys =
        if let Some(selected) = &operator_state.selected_verifier_pubkeys {
            selected.clone()
        } else {
            let mut selected = operator_state
                .candidates
                .iter()
                .filter(|candidate| candidate.gc_data.is_some())
                .map(|candidate| candidate.verifier_pubkey)
                .collect::<Vec<_>>();
            selected.sort_by_key(|candidate| candidate.to_bytes());
            selected.truncate(required_slots);
            selected
        };
    seal_selected_verifiers(operator_state, selected_verifier_pubkeys)?;
    let bitvm_gc_circuit_datas = selected_gc_data(operator_state)?;
    let mut obsolete_setup_outbox_ids = vec![format!("init-graph:{graph_id}")];
    obsolete_setup_outbox_ids.extend(operator_state.candidates.iter().map(|candidate| {
        format!("cut-circuits:{instance_id}:{graph_id}:{}", candidate.verifier_pubkey)
    }));
    if let Err(error) = save_babe_setup_state(&context.local_db, instance_id, graph_id, &state) {
        tracing::error!(
            event = "operator_graph_creation",
            outcome = "failed",
            stage = "babe_state_persist",
            candidate_index,
            error = %error,
            "failed to persist complete operator BABE setup state"
        );
        return Err(error).context("persist complete operator BABE setup state");
    }
    tracing::info!(
        event = "operator_graph_creation",
        outcome = "all_soldering_collected",
        verifier_slots = bitvm_gc_circuit_datas.len(),
        "all verifier soldering proofs are ready to build the graph"
    );

    let instance_params = get_instance_parameters(&context.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;

    let (graph_nonce, cur_prekickoff_txn) =
        match get_current_prekickoff_tx(&context.local_db, &local_operator_pubkey).await? {
            Some((graph_nonce, prekickoff_tx)) => (graph_nonce, prekickoff_tx),
            None => {
                (0, build_genesis_prekickoff_tx(&context.btc_client, &context.goat_client).await?)
            }
        };
    let prekickoff_params =
        build_prekickoff_params(&context.btc_client, graph_nonce, cur_prekickoff_txn).await?;

    let graph_build_started_at = Instant::now();
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "graph_build",
        outcome = "started",
        verifier_slots = bitvm_gc_circuit_datas.len(),
        graph_nonce,
        "building graph parameters from verified soldering proofs"
    );
    let mut graph_params = build_graph_params(
        &context.local_db,
        &context.goat_client,
        instance_params,
        prekickoff_params,
        bitvm_gc_circuit_datas,
        graph_nonce,
        graph_id,
    )
    .await?;

    let challenge_init_txid = generate_bitvm_graph(graph_params.clone())?
        .watchtower_challenge_init
        .tx()
        .compute_txid()
        .to_byte_array();
    graph_params.pubin_disprove_constant =
        get_guest_constant_value(graph_id, challenge_init_txid, &graph_params.watchtower_pubkeys)?;
    let mut graph = generate_bitvm_graph(graph_params)?;
    anyhow::ensure!(
        graph.watchtower_challenge_init.tx().compute_txid().to_byte_array() == challenge_init_txid,
        "Operator constant unexpectedly changes the watchtower challenge init transaction"
    );
    operator_pre_sign(operator_master_key.master_keypair(), &mut graph)?;

    let graph = graph.to_simplified()?;
    tracing::info!(
        event = "operator_soldering_proof",
        stage = "graph_build",
        outcome = "completed",
        graph_nonce,
        elapsed_ms = graph_build_started_at.elapsed().as_millis(),
        "built operator-pre-signed graph"
    );
    let definition_hash = hex::encode(graph.parameters_hash()?);
    tracing::info!(
        event = "operator_graph_creation",
        outcome = "started",
        stage = "definition_store",
        graph_nonce,
        definition_hash = %definition_hash,
        "storing operator-pre-signed graph definition"
    );
    if let Err(error) = store_operator_presigned_graph(&context.local_db, &graph).await {
        tracing::error!(
            event = "operator_graph_creation",
            outcome = "failed",
            stage = "definition_store",
            graph_nonce,
            definition_hash = %definition_hash,
            error = %error,
            "failed to store operator-pre-signed graph definition"
        );
        return Err(error).context("store operator-pre-signed graph definition");
    }
    tracing::info!(
        event = "operator_graph_creation",
        outcome = "committed",
        stage = "definition_store",
        graph_nonce,
        definition_hash = %definition_hash,
        "stored operator-pre-signed graph definition"
    );

    let message = GOATMessage::new(
        Actor::All,
        GOATMessageContent::CreateGraph(CreateGraph { instance_id, graph_id, graph_nonce, graph }),
    );
    let serialized = message.serialize_message().await?;
    let outbox_id = format!("create-graph:{graph_id}");
    let mut storage = context.local_db.acquire().await?;
    storage
        .insert_p2p_outbox_message(&outbox_id, message.content.event_type(), &serialized)
        .await?;
    let mut cancelled_setup_messages = 0;
    for setup_outbox_id in obsolete_setup_outbox_ids {
        cancelled_setup_messages +=
            storage.cancel_p2p_outbox_message(&setup_outbox_id).await? as u64;
    }
    drop(storage);
    tracing::info!(
        event = "operator_graph_creation",
        outcome = "enqueued",
        stage = "create_graph_outbox",
        graph_nonce,
        definition_hash = %definition_hash,
        outbox_id,
        cancelled_setup_messages,
        "enqueued CreateGraph for swarm publication"
    );

    // The outbox is durable before this cleanup. A process crash before
    // insertion leaves the session for inbox recovery; a crash after insertion
    // leaves the outbox for swarm publication.
    let mut storage = context.local_db.acquire().await?;
    let deleted_pending_sessions = storage
        .delete_pending_graph_init(&instance_id, &local_operator_pubkey.to_string())
        .await
        .context("delete pending graph session after CreateGraph outbox enqueue")?;
    tracing::info!(
        event = "operator_graph_creation",
        outcome = "completed",
        stage = "pending_session_delete",
        graph_nonce,
        definition_hash = %definition_hash,
        deleted_pending_sessions,
        "deleted pending graph session after CreateGraph outbox enqueue"
    );

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_confirm_instance_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    // triggered by PeginDeposit tx
    // 1. read & check parameters
    let instance_params = match read_instance_info_from_goat(ctx.goat_client, instance_id).await {
        Ok(v) => v,
        Err(e) => {
            if should_ignore_invalid_pegin_data(&e, instance_id) {
                return Ok(());
            }
            bail!(e)
        }
    };
    let pegin_deposit_txid = instance_params.build_pegin_tx()?.0.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &pegin_deposit_txid).await? {
        tracing::warn!(
            "Ignore ConfirmInstance for {instance_id}: pegin deposit tx {pegin_deposit_txid} not found on chain"
        );
        return Ok(());
    }
    // 2. save the instance data to local db
    store_instance_parameters(ctx.local_db, &instance_params).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_create_graph_verifier(
    context: &HeavyTaskContext,
    instance_id: Uuid,
    graph_id: Uuid,
    graph_nonce: u64,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    if !message_identity_matches(
        "CreateGraph",
        instance_id,
        graph_id,
        Some(graph_nonce),
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return Ok(());
    }

    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &local_verifier_pubkey)?
    else {
        return Ok(());
    };

    let full_graph = BitvmGcGraph::from_simplified(graph)?;
    validate_verifier_slot(&full_graph, verifier_index)?;
    verify_graph_operator_pre_signatures(&full_graph)
        .context("verify operator pre-signatures before endorsing graph parameters")?;
    let Some(verifier_state) = load_babe_setup_state(&context.local_db, instance_id, graph_id)?
        .and_then(|state| state.verifier)
    else {
        tracing::warn!(
            "Ignore CreateGraph for {instance_id}:{graph_id}: missing local BABE verifier state"
        );
        return Ok(());
    };
    if verifier_state.verifier_pubkey != local_verifier_pubkey {
        tracing::warn!(
            "Ignore CreateGraph for {instance_id}:{graph_id}: local BABE verifier pubkey mismatch"
        );
        return Ok(());
    }
    let Some(soldering_proof_ready) = verifier_state.soldering_proof_ready.clone() else {
        tracing::warn!(
            "Ignore CreateGraph for {instance_id}:{graph_id}: local verifier has no soldering proof"
        );
        return Ok(());
    };
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        soldering_proof_ready.candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = read_soldering_proof_store_payload(&payload_path)
        .await
        .context("read local soldering proof payload for graph params endorsement")?;
    let payload = decode_soldering_proof_payload(&soldering_proof_ready, &payload)?;
    let (_opened, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand local soldering proof payload for graph params endorsement")?;
    if finalized.len() != BABE_M_CC {
        bail!("local verifier finalized BABE instance count mismatch");
    }
    let epk = &verifier_state.setup_package.commits[finalized[0].index].epk;
    let prover_state =
        build_babe_prover_state(&verifier_state.setup_package, finalized, soldering)?;
    let expected_gc_data =
        extract_gc_circuit_data(local_verifier_pubkey, epk, &prover_state.h_msgs)?;
    if graph.parameters.gc_data[verifier_index] != expected_gc_data {
        tracing::warn!(
            "Ignore CreateGraph for {instance_id}:{graph_id}: graph GC data for local verifier does not match local soldering proof"
        );
        return Ok(());
    }

    let canonical_graph_params_hash = graph.canonical_graph_params_hash()?;
    let signature = sign_verifier_graph_params(verifier_master_key.master_keypair(), graph)?;
    let message = GOATMessage::new(
        Actor::Committee,
        GOATMessageContent::VerifierGraphParamsEndorsement(VerifierGraphParamsEndorsement {
            instance_id,
            graph_id,
            verifier_pubkey: local_verifier_pubkey,
            verifier_index,
            canonical_graph_params_hash,
            signature,
        }),
    );
    let serialized = message.serialize_message().await?;
    let endorsement_outbox_id =
        format!("verifier-graph-params-endorsement:{graph_id}:{verifier_index}");
    let mut storage = context.local_db.acquire().await?;
    storage
        .enqueue_p2p_outbox_message(
            &endorsement_outbox_id,
            message.content.event_type(),
            &serialized,
        )
        .await?;
    let cancelled_gen_circuits = storage
        .cancel_p2p_outbox_message(&format!(
            "gen-circuits:{instance_id}:{graph_id}:{local_verifier_pubkey}"
        ))
        .await?;
    let cancelled_soldering_proof = storage
        .cancel_p2p_outbox_message(&format!(
            "soldering-proof-ready:{graph_id}:{}:{}",
            soldering_proof_ready.candidate_index,
            hex::encode(soldering_proof_ready.payload_hash),
        ))
        .await?;

    tracing::info!(
        event = "verifier_graph_validation",
        outcome = "endorsement_enqueued",
        instance_id = %instance_id,
        graph_id = %graph_id,
        verifier_index,
        endorsement_outbox_id,
        cancelled_gen_circuits,
        cancelled_soldering_proof,
        "validated CreateGraph and enqueued verifier graph params endorsement"
    );
    Ok(())
}

async fn try_start_graph_committee_setup(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    let verifier_endorsements =
        get_verifier_graph_params_endorsements_for_graph(ctx.local_db, instance_id, graph_id)
            .await?;
    if verifier_endorsements.len() < graph.parameters.gc_data.len() {
        tracing::info!(
            "Defer CreateGraph for {instance_id}:{graph_id}: waiting for verifier graph params endorsements ({}/{})",
            verifier_endorsements.len(),
            graph.parameters.gc_data.len()
        );
        return Ok(());
    }
    let validation = validate_init_graph(
        ctx.local_db,
        ctx.btc_client,
        ctx.goat_client,
        graph,
        &verifier_endorsements,
    )
    .await;
    ctx.metrics_state.record_graph_validation(validation.is_ok());
    if let Err(e) = validation {
        if should_ignore_invalid_graph(&e, instance_id, graph_id, "CreateGraph", None) {
            return Ok(());
        }
        bail!(e)
    };

    // generate Musig2 nonces & broadcast NonceGeneration
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let full_graph = BitvmGcGraph::from_simplified(graph)?;
    let (pub_nonces, _, nonce_sigs) =
        committee_master_key.nonces_for_graph_job_with_keypair(&full_graph, instance_keypair)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    if get_committee_partial_sigs_for_graph_member(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_committee_pubkey,
    )
    .await?
    .is_some()
    {
        tracing::warn!(
            "Ignore CreateGraph for {instance_id}:{graph_id}: local committee partial signatures already exist"
        );
        return Ok(());
    }
    let message_content = GOATMessageContent::NonceGeneration(NonceGeneration {
        instance_id,
        graph_id,
        committee_pubkey: local_committee_pubkey,
        pub_nonces: pub_nonces.clone(),
        nonce_sigs,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    store_committee_pub_nonces_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        local_committee_pubkey,
        pub_nonces,
    )
    .await?;
    maybe_vote_and_presign_graph(ctx, instance_id, graph_id, graph).await
}

async fn graph_nonce_consensus_context(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<Option<(BitvmGcGraph, Vec<PublicKey>, CommitteeAggNonces, [u8; 32])>> {
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if pub_nonces_unchecked.len() < committee_pubkeys.len() {
        return Ok(None);
    }

    let full_graph = BitvmGcGraph::from_simplified(graph)?;
    let verifier_num = full_graph.parameters.gc_data.len();
    let watchtower_num = full_graph.parameters.watchtower_pubkeys.len();
    let mut checked_pub_nonces = Vec::with_capacity(pub_nonces_unchecked.len());
    for (pubkey, pub_nonces) in pub_nonces_unchecked {
        pub_nonces.validate_length(watchtower_num, verifier_num).map_err(|error| {
            anyhow!("committee public nonces from {pubkey} have invalid length: {error}")
        })?;
        checked_pub_nonces.push((pubkey, pub_nonces));
    }
    let ordered_pub_nonces = order_committee_values(
        &committee_pubkeys,
        checked_pub_nonces,
        "graph committee pub nonces",
    )?;
    let agg_nonces = nonces_aggregation(&ordered_pub_nonces)?;
    let consensus_hash =
        committee_nonce_consensus_hash(&full_graph, &committee_pubkeys, &ordered_pub_nonces)?;
    Ok(Some((full_graph, committee_pubkeys, agg_nonces, consensus_hash)))
}

async fn maybe_vote_and_presign_graph(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    let Some((mut full_graph, committee_pubkeys, agg_nonces, consensus_hash)) =
        graph_nonce_consensus_context(ctx, instance_id, graph_id, graph).await?
    else {
        return Ok(());
    };

    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    if get_committee_partial_sigs_for_graph_member(
        ctx.local_db,
        instance_id,
        graph_id,
        &local_committee_pubkey,
    )
    .await?
    .is_some()
    {
        return endorse_graph_if_presigned(ctx, instance_id, graph_id, &full_graph).await;
    }

    let consensus_votes =
        get_committee_agg_nonce_consensus_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if let Some((_, stored_hash, _)) = consensus_votes
        .iter()
        .find(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
        && *stored_hash != consensus_hash
    {
        bail!(SpecialError::InvalidGraph(format!(
            "local committee agg nonce consensus differs for graph {graph_id}"
        )));
    }
    if !consensus_votes
        .iter()
        .any(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
    {
        let signature =
            SECP256K1.sign_schnorr(&SecpMessage::from_digest(consensus_hash), &instance_keypair);
        store_committee_agg_nonce_consensus_for_graph(
            ctx.local_db,
            instance_id,
            graph_id,
            local_committee_pubkey,
            consensus_hash,
            signature,
        )
        .await?;
        let message_content = GOATMessageContent::AggNonceConsensus(AggNonceConsensus {
            instance_id,
            graph_id,
            committee_pubkey: local_committee_pubkey,
            consensus_hash,
            signature,
        });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;
    }

    let consensus_votes =
        get_committee_agg_nonce_consensus_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if consensus_votes.len() < committee_pubkeys.len() {
        tracing::info!(
            "Defer committee pre-sign for {instance_id}:{graph_id}: waiting for agg nonce consensus ({}/{})",
            consensus_votes.len(),
            committee_pubkeys.len(),
        );
        return Ok(());
    }
    let ordered_votes = order_committee_values(
        &committee_pubkeys,
        consensus_votes
            .into_iter()
            .map(|(committee_pubkey, consensus_hash, signature)| {
                (committee_pubkey, (consensus_hash, signature))
            })
            .collect(),
        "graph committee agg nonce consensus",
    )?;
    for (committee_pubkey, (received_hash, signature)) in
        committee_pubkeys.iter().zip(ordered_votes)
    {
        if received_hash != consensus_hash {
            bail!(SpecialError::InvalidGraph(format!(
                "committee agg nonce consensus differs for graph {graph_id} and committee {committee_pubkey}"
            )));
        }
        SECP256K1
            .verify_schnorr(
                &signature,
                &SecpMessage::from_digest(consensus_hash),
                &XOnlyPublicKey::from(*committee_pubkey),
            )
            .map_err(|error| {
                SpecialError::InvalidGraph(format!(
                    "invalid agg nonce consensus signature for graph {graph_id} and committee {committee_pubkey}: {error}"
                ))
            })?;
    }

    let (_, sec_nonces, _) =
        committee_master_key.nonces_for_graph_job_with_keypair(&full_graph, instance_keypair)?;
    let committee_partial_sigs =
        committee_pre_sign(instance_keypair, sec_nonces, agg_nonces.clone(), &mut full_graph)?;
    store_committee_partial_sigs_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        local_committee_pubkey,
        committee_partial_sigs.clone(),
    )
    .await?;
    let message_content = GOATMessageContent::CommitteePresign(CommitteePresign {
        instance_id,
        graph_id,
        committee_pubkey: local_committee_pubkey,
        committee_partial_sigs,
        agg_nonces,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    endorse_graph_if_presigned(ctx, instance_id, graph_id, &full_graph).await
}

async fn endorse_graph_if_presigned(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
) -> Result<()> {
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let committee_partial_sigs =
        get_committee_partial_sigs_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if committee_partial_sigs.len() != committee_pubkeys.len() {
        return Ok(());
    }

    let committee_sig_for_graph = endorse_graph(ctx.goat_client, graph).await?;
    let committee_sig_for_params = endorse_graph_params(graph).await?;
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    let committee_evm_address = get_node_goat_address()
        .ok_or_else(|| anyhow!("failed to get node goat address".to_string()))?;
    let message_content = GOATMessageContent::EndorseGraph(EndorseGraph {
        instance_id,
        graph_id,
        committee_pubkey: local_committee_pubkey,
        committee_sig_for_graph: committee_sig_for_graph.as_bytes().to_vec(),
        committee_sig_for_params: committee_sig_for_params.as_bytes().to_vec(),
        committee_evm_address,
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_create_graph_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph_nonce: u64,
    graph: &SimplifiedBitvmGcGraph,
    content: &GOATMessageContent,
) -> Result<()> {
    if !message_identity_matches(
        "CreateGraph",
        instance_id,
        graph_id,
        Some(graph_nonce),
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return Ok(());
    }

    // received from Operator
    if graph.parameters.graph_nonce > 0 {
        let previous_nonce = graph.parameters.graph_nonce - 1;
        match get_graph_id_by_nonce(ctx.local_db, previous_nonce, &graph.parameters.operator_pubkey)
            .await?
        {
            Some((previous_instance_id, previous_graph_id)) => {
                let Some(previous_graph) =
                    get_graph(ctx.local_db, previous_instance_id, previous_graph_id).await?
                else {
                    if let Err(e) = try_send_sync_graph_request(
                        ctx.swarm,
                        ctx.goat_client,
                        previous_instance_id,
                        previous_graph_id,
                    )
                    .await
                    {
                        tracing::warn!(
                            "Failed to send SyncGraphRequest for previous graph {previous_instance_id}:{previous_graph_id}: {e}"
                        );
                    }
                    let message = make_message(ctx, content);
                    push_local_unhandled_messages_with_reason(
                        ctx.local_db,
                        graph_id,
                        &message,
                        60,
                        MessageDeferReason::PreviousGraphPending,
                        "previous graph definition is not available locally",
                    )
                    .await?;
                    tracing::info!(
                        "Defer CreateGraph for {instance_id}:{graph_id}: waiting for previous graph raw data {previous_instance_id}:{previous_graph_id}"
                    );
                    return Ok(());
                };
                if !previous_graph.committee_pre_signed() {
                    let message = make_message(ctx, content);
                    push_local_unhandled_messages_with_reason(
                        ctx.local_db,
                        graph_id,
                        &message,
                        60,
                        MessageDeferReason::PreviousGraphPending,
                        "previous graph is waiting for committee pre-signatures",
                    )
                    .await?;
                    tracing::info!(
                        "Defer CreateGraph for {instance_id}:{graph_id}: waiting for previous graph {previous_instance_id}:{previous_graph_id} to be committee pre-signed"
                    );
                    return Ok(());
                }
            }
            None => {
                let message = make_message(ctx, content);
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    graph_id,
                    &message,
                    60,
                    MessageDeferReason::PreviousGraphPending,
                    "previous graph nonce is not available locally",
                )
                .await?;
                tracing::info!(
                    "Defer CreateGraph for {instance_id}:{graph_id}: previous graph with nonce {previous_nonce} is not available locally"
                );
                return Ok(());
            }
        }
    }

    // 1. check graph data & operator stake without verifier params endorsements; those may arrive later.
    let validation =
        validate_init_graph_base(ctx.local_db, ctx.btc_client, ctx.goat_client, graph).await;
    ctx.metrics_state.record_graph_validation(validation.is_ok());
    if let Err(e) = validation {
        if should_ignore_invalid_graph(&e, instance_id, graph_id, "CreateGraph", None) {
            return Ok(());
        }
        bail!(e)
    };
    // 2. save the graph data to local db
    store_operator_presigned_graph(ctx.local_db, graph).await?;
    // 3. start committee setup once verifier params endorsements are complete
    try_start_graph_committee_setup(ctx, instance_id, graph_id, graph).await
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_verifier_graph_params_endorsement_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    verifier_pubkey: &PublicKey,
    verifier_index: usize,
    canonical_graph_params_hash: [u8; 32],
    signature: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    if !ctx.is_self_peer
        && !ctx.goat_client.committee_mana_is_verifier(&ctx.from_peer_id.to_bytes()).await?
    {
        tracing::warn!(
            "Ignore VerifierGraphParamsEndorsement for {instance_id}:{graph_id}: sender {} is not a registered verifier",
            ctx.from_peer_id
        );
        return Ok(());
    }

    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        &message,
    )
    .await?
    {
        Some(graph) => graph,
        None => return Ok(()),
    };
    let expected_hash = graph.canonical_graph_params_hash()?;
    if canonical_graph_params_hash != expected_hash {
        tracing::warn!(
            "Ignore VerifierGraphParamsEndorsement for {instance_id}:{graph_id} from {verifier_pubkey}: canonical graph params hash mismatch"
        );
        return Ok(());
    }
    if verifier_index >= graph.parameters.gc_data.len() {
        tracing::warn!(
            "Ignore VerifierGraphParamsEndorsement for {instance_id}:{graph_id} from {verifier_pubkey}: verifier index {verifier_index} out of range"
        );
        return Ok(());
    }
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != *verifier_pubkey {
        tracing::warn!(
            "Ignore VerifierGraphParamsEndorsement for {instance_id}:{graph_id}: verifier pubkey does not own slot {verifier_index}"
        );
        return Ok(());
    }
    if !verify_verifier_graph_params_endorsement(verifier_pubkey, &graph, signature)? {
        tracing::warn!(
            "Ignore VerifierGraphParamsEndorsement for {instance_id}:{graph_id} from {verifier_pubkey}: invalid signature"
        );
        return Ok(());
    }

    store_verifier_graph_params_endorsement(
        ctx.local_db,
        instance_id,
        graph_id,
        *verifier_pubkey,
        verifier_index,
        *signature,
    )
    .await?;
    try_start_graph_committee_setup(ctx, instance_id, graph_id, &graph).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "NonceGeneration",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonces & nonce signatures
    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        &message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(()),
    };
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.parameters.gc_data.len();
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
        watchtower_num,
        verifier_num,
    )? {
        tracing::warn!(
            "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    // 2. Save immutable pub_nonces for this committee member and graph.
    store_committee_pub_nonces_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        pub_nonces.clone(),
    )
    .await?;
    maybe_vote_and_presign_graph(ctx, instance_id, graph_id, &graph).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_agg_nonce_consensus_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    received_consensus_hash: [u8; 32],
    signature: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "AggNonceConsensus",
    )
    .await?
    {
        return Ok(());
    }

    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        &message,
    )
    .await?
    {
        Some(graph) => graph,
        None => return Ok(()),
    };
    let Some((_, _, _, expected_consensus_hash)) =
        graph_nonce_consensus_context(ctx, instance_id, graph_id, &graph).await?
    else {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces before validating agg nonce consensus",
        )
        .await?;
        tracing::info!(
            "Defer AggNonceConsensus for {instance_id}:{graph_id}: waiting for committee pub nonces"
        );
        return Ok(());
    };
    if received_consensus_hash != expected_consensus_hash {
        tracing::warn!(
            "Ignore AggNonceConsensus for {instance_id}:{graph_id} from {}: consensus hash mismatch",
            received_committee_pubkey,
        );
        return Ok(());
    }
    if SECP256K1
        .verify_schnorr(
            signature,
            &SecpMessage::from_digest(expected_consensus_hash),
            &XOnlyPublicKey::from(*received_committee_pubkey),
        )
        .is_err()
    {
        tracing::warn!(
            "Ignore AggNonceConsensus for {instance_id}:{graph_id} from {}: invalid signature",
            received_committee_pubkey,
        );
        return Ok(());
    }
    store_committee_agg_nonce_consensus_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        received_consensus_hash,
        *signature,
    )
    .await?;
    maybe_vote_and_presign_graph(ctx, instance_id, graph_id, &graph).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nonce_generation_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "NonceGeneration",
    )
    .await?
    {
        return Ok(());
    }
    let graph = match get_graph(ctx.local_db, instance_id, graph_id).await? {
        Some(g) => g,
        None => {
            tracing::warn!(
                "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: graph not found, maybe belongs to another Operator",
                received_committee_pubkey.to_string()
            );
            return Ok(());
        }
    };
    let verifier_num = graph.parameters.gc_data.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    // 1. check pub_nonces & nonce signatures
    let committee_xonly_pubkey = XOnlyPublicKey::from(*received_committee_pubkey);
    if !verify_nonce_signatures(
        &committee_xonly_pubkey,
        pub_nonces,
        nonce_sigs,
        watchtower_num,
        verifier_num,
    )? {
        tracing::warn!(
            "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces or nonce_sigs",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    if let Err(e) = pub_nonces.validate_length(watchtower_num, verifier_num) {
        tracing::warn!(
            "Ignore NonceGeneration for {instance_id}:{graph_id} from {}: invalid pub_nonces length: {e}",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    // 2. Save immutable pub_nonces for this committee member and graph.
    store_committee_pub_nonces_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        pub_nonces.clone(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local db, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    if let Some((finalized_graph, _)) = try_finalize_graph(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        Some(&graph),
        true,
    )
    .await?
    {
        refresh_newly_finalized_graph(ctx, instance_id, graph_id, &finalized_graph).await?;
    }
    Ok(())
}

async fn validate_committee_presign_for_graph(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_partial_sigs: &CommitteePartialSignatures,
    received_agg_nonces: &CommitteeAggNonces,
    content: &GOATMessageContent,
) -> Result<Option<BitvmGcGraph>> {
    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        &message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(None),
    };
    let graph = BitvmGcGraph::from_simplified(&graph)?;
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_graph(ctx.local_db, instance_id, graph_id).await?;
    if pub_nonces_unchecked.len() != committee_pubkeys.len() {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces",
        )
        .await?;
        tracing::info!(
            "Defer CommitteePresign for {instance_id}:{graph_id}: waiting for committee pub nonces"
        );
        return Ok(None);
    }
    let received_pub_nonces = match pub_nonces_unchecked
        .iter()
        .find(|(pubkey, _)| pubkey == received_committee_pubkey)
        .map(|(_, pub_nonces)| pub_nonces.clone())
    {
        Some(pub_nonces) => pub_nonces,
        None => {
            tracing::warn!(
                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: missing signer pub nonces",
                received_committee_pubkey
            );
            return Ok(None);
        }
    };
    let pub_nonces = match order_committee_values(
        &committee_pubkeys,
        pub_nonces_unchecked,
        "graph committee pub nonces",
    ) {
        Ok(pub_nonces) => pub_nonces,
        Err(e) => {
            tracing::warn!(
                "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: invalid pub nonce set: {e}",
                received_committee_pubkey
            );
            return Ok(None);
        }
    };
    let agg_nonces = nonces_aggregation(&pub_nonces)?;
    if &agg_nonces != received_agg_nonces {
        tracing::warn!(
            "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: agg_nonces mismatch",
            received_committee_pubkey
        );
        return Ok(None);
    }
    if let Err(e) = verify_graph_committee_partial_sigs(
        &graph,
        &committee_pubkeys,
        received_committee_pubkey,
        &received_pub_nonces,
        &agg_nonces,
        committee_partial_sigs,
    ) {
        tracing::warn!(
            "Ignore CommitteePresign for {instance_id}:{graph_id} from {}: invalid partial signatures: {e}",
            received_committee_pubkey
        );
        return Ok(None);
    }
    Ok(Some(graph))
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_committee_presign_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_partial_sigs: &CommitteePartialSignatures,
    _agg_nonces: &CommitteeAggNonces,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "CommitteePresign",
    )
    .await?
    {
        return Ok(());
    }
    let graph = match validate_committee_presign_for_graph(
        ctx,
        instance_id,
        graph_id,
        received_committee_pubkey,
        committee_partial_sigs,
        _agg_nonces,
        content,
    )
    .await?
    {
        Some(graph) => graph,
        None => return Ok(()),
    };
    // 1. save the validated committee partial sigs to local db
    store_committee_partial_sigs_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        committee_partial_sigs.clone(),
    )
    .await?;
    // 2. This also covers the case where the local partial signature was the last one and is
    // not delivered back by gossip.
    endorse_graph_if_presigned(ctx, instance_id, graph_id, &graph).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_committee_presign_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_partial_sigs: &CommitteePartialSignatures,
    _agg_nonces: &CommitteeAggNonces,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        "CommitteePresign",
    )
    .await?
    {
        return Ok(());
    }
    if validate_committee_presign_for_graph(
        ctx,
        instance_id,
        graph_id,
        received_committee_pubkey,
        committee_partial_sigs,
        _agg_nonces,
        content,
    )
    .await?
    .is_none()
    {
        return Ok(());
    }
    // 1. save the validated committee partial sigs to local db
    store_committee_partial_sigs_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        committee_partial_sigs.clone(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local database, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    if let Some((finalized_graph, _)) = try_finalize_graph(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        None,
        true,
    )
    .await?
    {
        refresh_newly_finalized_graph(ctx, instance_id, graph_id, &finalized_graph).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_endorse_graph_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    received_committee_pubkey: &PublicKey,
    committee_sig_for_graph: &[u8],
    committee_sig_for_params: &[u8],
    committee_evm_address: &alloy::primitives::Address,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee_with_evm(
        ctx,
        instance_id,
        Some(graph_id),
        received_committee_pubkey,
        committee_evm_address,
        "EndorseGraph",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check endorsement signature
    let graph = match get_graph(ctx.local_db, instance_id, graph_id).await? {
        Some(g) => g,
        None => {
            tracing::warn!(
                "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: graph not found, maybe belongs to another Operator",
                received_committee_pubkey.to_string()
            );
            return Ok(());
        }
    };
    let full_graph = BitvmGcGraph::from_simplified(&graph)?;
    if let Err(e) = verify_graph_endorsement(
        ctx.goat_client,
        committee_evm_address,
        &full_graph,
        committee_sig_for_graph,
    )
    .await
    {
        tracing::warn!(
            "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: invalid endorsement signature: {e}",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    match verify_graph_params_endorsement(
        committee_evm_address,
        &full_graph,
        committee_sig_for_params,
    ) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: invalid params endorsement signature",
                received_committee_pubkey.to_string()
            );
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(
                "Ignore EndorseGraph for {instance_id}:{graph_id} from {}: invalid params endorsement signature: {e}",
                received_committee_pubkey.to_string()
            );
            return Ok(());
        }
    }
    // 2. save the endorsement signature to local db
    store_committee_endorsement_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        *received_committee_pubkey,
        *committee_evm_address,
        committee_sig_for_graph.to_owned(),
        committee_sig_for_params.to_owned(),
    )
    .await?;
    // 3. if received enough endorsement signatures, mark the graph as endorsed, send the graph to local database, broadcast GraphFinalize
    // Operator may receive EndorseGraph, CommitteePresign or NonceGeneration messages in any order
    // So we need to check if we have collected enough endorsements, pub_nonces and partial_sigs every time we receive them
    if let Some((finalized_graph, _)) = try_finalize_graph(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        Some(&graph),
        true,
    )
    .await?
    {
        refresh_newly_finalized_graph(ctx, instance_id, graph_id, &finalized_graph).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_graph_finalize_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph_nonce: u64,
    graph: &SimplifiedBitvmGcGraph,
    endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
    params_endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
) -> Result<()> {
    if !message_identity_matches(
        "GraphFinalize",
        instance_id,
        graph_id,
        Some(graph_nonce),
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return Ok(());
    }

    // received from Operator
    // 1. check graph data
    let validation = validate_finalized_graph(
        ctx.btc_client,
        ctx.goat_client,
        graph,
        endorse_sigs,
        params_endorse_sigs,
    )
    .await;
    ctx.metrics_state.record_graph_validation(validation.is_ok());
    if let Err(e) = validation {
        if should_ignore_invalid_graph(
            &e,
            instance_id,
            graph_id,
            "GraphFinalize",
            Some(&ctx.from_peer_id),
        ) {
            return Ok(());
        }
        bail!(e)
    }
    // 2. Store a finalized graph only when it upgrades the local graph.
    let _ = store_finalized_graph_if_needed(ctx.local_db, graph).await?;
    store_committee_endorsements_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        endorse_sigs.to_owned(),
        params_endorse_sigs.to_owned(),
    )
    .await?;
    // After storing, mark the graph as finalized for the instance threshold.
    mark_graph_as_endorsed(ctx.local_db, instance_id, graph_id).await?;
    try_transition_instance_to_presigned(ctx.local_db, instance_id).await?;
    let finalized_graph = BitvmGcGraph::from_simplified(graph)?;
    refresh_newly_finalized_graph(ctx, instance_id, graph_id, &finalized_graph).await?;
    // 3. if endorsed graph count >= threshold, generate & broadcast PeginConfirmNonce
    if has_required_presigned_graphs(ctx.local_db, instance_id).await? {
        let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
        let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
        let local_committee_pubkey = instance_keypair.public_key().into();
        let stored_pub_nonce = get_committee_pub_nonce_for_instance(
            ctx.local_db,
            instance_id,
            &local_committee_pubkey,
        )
        .await?;
        if stored_pub_nonce.is_none() {
            if get_committee_partial_sig_for_instance(
                ctx.local_db,
                instance_id,
                &local_committee_pubkey,
            )
            .await?
            .is_some()
            {
                tracing::warn!(
                    "Skip PeginConfirm nonce for {instance_id}: local committee partial signature already exists"
                );
            } else {
                let (_, pub_nonce, nonce_sig) = committee_master_key
                    .nonce_for_instance_job_with_keypair(
                        &graph.parameters.instance_parameters,
                        instance_keypair,
                    )?;
                let message_content = GOATMessageContent::PeginConfirmNonce(PeginConfirmNonce {
                    instance_id,
                    committee_pubkey: local_committee_pubkey,
                    pub_nonce: pub_nonce.clone(),
                    nonce_sig,
                });
                store_committee_pub_nonce_for_instance(
                    ctx.local_db,
                    instance_id,
                    local_committee_pubkey,
                    pub_nonce,
                )
                .await?;
                send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content))
                    .await?;
            }
        }
        maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await?;
    }
    // 4. (Relayer) try to call Gateway.postGraphData
    // GraphFinalize may come after PostReady, so we need to check it here
    if is_relayer() {
        let pegin_data = ctx.goat_client.gateway_get_pegin_data(&instance_id).await?;
        if pegin_data.status != PeginStatus::Withdrawable {
            // pegin not posted yet
            return Ok(());
        }
        let graph_data = ctx.goat_client.gateway_get_graph_data(&graph_id).await?;
        if graph_data.operator_pubkey != [0u8; 32] {
            // already posted
            return Ok(());
        }
        let graph = BitvmGcGraph::from_simplified(graph)?;
        let graph_data = build_graph_data(&graph)?;
        let endorse_sigs = endorse_sigs.iter().map(|(_, _, sig)| sig.clone()).collect::<Vec<_>>();
        ctx.goat_client
            .gateway_post_graph_data(&instance_id, &graph_id, &graph_data, &endorse_sigs)
            .await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_graph_finalize_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph_nonce: u64,
    graph: &SimplifiedBitvmGcGraph,
    endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
    params_endorse_sigs: &[(PublicKey, alloy::primitives::Address, Vec<u8>)],
) -> Result<()> {
    if !message_identity_matches(
        "GraphFinalize",
        instance_id,
        graph_id,
        Some(graph_nonce),
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return Ok(());
    }

    // received from Operator
    // 1. check graph data
    let validation = validate_finalized_graph(
        ctx.btc_client,
        ctx.goat_client,
        graph,
        endorse_sigs,
        params_endorse_sigs,
    )
    .await;
    ctx.metrics_state.record_graph_validation(validation.is_ok());
    if let Err(e) = validation {
        if should_ignore_invalid_graph(
            &e,
            instance_id,
            graph_id,
            "GraphFinalize",
            Some(&ctx.from_peer_id),
        ) {
            return Ok(());
        }
        bail!(e)
    }
    // 2. Store a finalized graph only when it upgrades the local graph.
    let _ = store_finalized_graph_if_needed(ctx.local_db, graph).await?;
    store_committee_endorsements_for_graph(
        ctx.local_db,
        instance_id,
        graph_id,
        endorse_sigs.to_owned(),
        params_endorse_sigs.to_owned(),
    )
    .await?;
    mark_graph_as_endorsed(ctx.local_db, instance_id, graph_id).await?;
    try_transition_instance_to_presigned(ctx.local_db, instance_id).await?;
    let finalized_graph = BitvmGcGraph::from_simplified(graph)?;
    refresh_newly_finalized_graph(ctx, instance_id, graph_id, &finalized_graph).await?;
    Ok(())
}

async fn pegin_confirm_nonce_consensus_context(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<
    Option<(
        BitvmGcInstanceParameters,
        Vec<PublicKey>,
        Vec<musig2::PubNonce>,
        musig2::AggNonce,
        [u8; 32],
    )>,
> {
    let instance_parameters = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces.len() < committee_pubkeys.len() {
        return Ok(None);
    }
    let ordered_pub_nonces =
        order_committee_values(&committee_pubkeys, pub_nonces, "pegin committee pub nonces")?;
    let agg_nonce = nonce_aggregation(&ordered_pub_nonces);
    let consensus_hash = pegin_confirm_nonce_consensus_hash(
        &instance_parameters,
        &committee_pubkeys,
        &ordered_pub_nonces,
    )?;
    Ok(Some((
        instance_parameters,
        committee_pubkeys,
        ordered_pub_nonces,
        agg_nonce,
        consensus_hash,
    )))
}

async fn has_complete_pegin_confirm_nonce_consensus(
    ctx: &HandlerContext<'_>,
    instance_id: Uuid,
    committee_pubkeys: &[PublicKey],
    consensus_hash: [u8; 32],
) -> Result<bool> {
    let consensus_votes =
        get_committee_agg_nonce_consensus_for_instance(ctx.local_db, instance_id).await?;
    if consensus_votes.len() != committee_pubkeys.len() {
        return Ok(false);
    }
    let ordered_votes = order_committee_values(
        committee_pubkeys,
        consensus_votes
            .into_iter()
            .map(|(committee_pubkey, vote_hash, signature)| {
                (committee_pubkey, (vote_hash, signature))
            })
            .collect(),
        "PeginConfirm agg nonce consensus",
    )?;
    for (committee_pubkey, (received_hash, signature)) in
        committee_pubkeys.iter().zip(ordered_votes)
    {
        ensure!(
            received_hash == consensus_hash,
            "committee PeginConfirm nonce consensus differs for instance {instance_id} and committee {committee_pubkey}"
        );
        SECP256K1
            .verify_schnorr(
                &signature,
                &SecpMessage::from_digest(consensus_hash),
                &XOnlyPublicKey::from(*committee_pubkey),
            )
            .map_err(|error| {
                SpecialError::InvalidPeginData(format!(
                    "invalid PeginConfirm nonce consensus signature for instance {instance_id} and committee {committee_pubkey}: {error}"
                ))
            })?;
    }
    Ok(true)
}

async fn broadcast_pegin_confirm_if_presigned(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    instance_parameters: &BitvmGcInstanceParameters,
    committee_pubkeys: &[PublicKey],
) -> Result<()> {
    if !is_relayer() {
        return Ok(());
    }
    let pub_nonces = get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    let partial_sigs = get_committee_partial_sigs_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces.len() != committee_pubkeys.len() || partial_sigs.len() != committee_pubkeys.len()
    {
        return Ok(());
    }
    let pub_nonces =
        order_committee_values(committee_pubkeys, pub_nonces, "pegin committee pub nonces")?;
    let partial_sigs =
        order_committee_values(committee_pubkeys, partial_sigs, "pegin committee partial sigs")?;
    let mut pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let context = instance_parameters.get_base_context();
    let full_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, &agg_nonce)
        .map_err(|error| {
            anyhow!("Failed to aggregate PeginConfirm signatures for {instance_id}: {error}")
        })?;
    let connector_z = instance_parameters.connector_z();
    pegin_confirm.push_input_0_signature(&connector_z, full_sig);
    let result = broadcast_tx(ctx.btc_client, pegin_confirm.tx()).await;
    ctx.metrics_state.record_pegin_confirm(result.is_ok());
    result?;
    Ok(())
}

async fn maybe_vote_and_sign_pegin_confirm(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
) -> Result<()> {
    let Some((instance_parameters, committee_pubkeys, _pub_nonces, agg_nonce, consensus_hash)) =
        pegin_confirm_nonce_consensus_context(ctx, instance_id).await?
    else {
        return Ok(());
    };
    let committee_master_key = CommitteeMasterKey::new(get_bitvm_key()?);
    let instance_keypair = load_committee_instance_keypair(&committee_master_key, instance_id)?;
    let local_committee_pubkey = instance_keypair.public_key().into();
    if get_committee_partial_sig_for_instance(ctx.local_db, instance_id, &local_committee_pubkey)
        .await?
        .is_some()
    {
        return broadcast_pegin_confirm_if_presigned(
            ctx,
            instance_id,
            &instance_parameters,
            &committee_pubkeys,
        )
        .await;
    }

    let consensus_votes =
        get_committee_agg_nonce_consensus_for_instance(ctx.local_db, instance_id).await?;
    if let Some((_, stored_hash, _)) = consensus_votes
        .iter()
        .find(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
        && *stored_hash != consensus_hash
    {
        bail!(SpecialError::InvalidPeginData(format!(
            "local PeginConfirm nonce consensus differs for instance {instance_id}"
        )));
    }
    if !consensus_votes
        .iter()
        .any(|(committee_pubkey, _, _)| *committee_pubkey == local_committee_pubkey)
    {
        let signature =
            SECP256K1.sign_schnorr(&SecpMessage::from_digest(consensus_hash), &instance_keypair);
        store_committee_agg_nonce_consensus_for_instance(
            ctx.local_db,
            instance_id,
            local_committee_pubkey,
            consensus_hash,
            signature,
        )
        .await?;
        let message_content =
            GOATMessageContent::PeginConfirmNonceConsensus(PeginConfirmNonceConsensus {
                instance_id,
                committee_pubkey: local_committee_pubkey,
                consensus_hash,
                signature,
            });
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;
    }
    if !has_complete_pegin_confirm_nonce_consensus(
        ctx,
        instance_id,
        &committee_pubkeys,
        consensus_hash,
    )
    .await?
    {
        tracing::info!(
            "Defer PeginConfirm partial signature for {instance_id}: waiting for agg nonce consensus"
        );
        return Ok(());
    }

    let (sec_nonce, _, _) = committee_master_key
        .nonce_for_instance_job_with_keypair(&instance_parameters, instance_keypair)?;
    let mut pegin_confirm = instance_parameters.build_pegin_tx()?.1;
    let committee_context = instance_parameters.get_committee_context(instance_keypair)?;
    let partial_sig = pegin_confirm
        .sign_input_0_musig2(&committee_context, &sec_nonce, &agg_nonce)
        .map_err(|error| anyhow!("Failed to sign PeginConfirm for {instance_id}: {error}"))?;
    let endorse_sig =
        endorse_pegin(ctx.goat_client, instance_id, &pegin_confirm.tx().compute_txid()).await?;
    store_committee_partial_sig_for_instance(
        ctx.local_db,
        instance_id,
        local_committee_pubkey,
        partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        ctx.local_db,
        instance_id,
        local_committee_pubkey,
        endorse_sig.as_bytes().to_vec(),
    )
    .await?;
    let message_content = GOATMessageContent::PeginConfirmPartialSig(PeginConfirmPartialSig {
        instance_id,
        committee_pubkey: local_committee_pubkey,
        partial_sig,
        endorse_sig: endorse_sig.as_bytes().to_vec(),
    });
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, message_content)).await?;
    broadcast_pegin_confirm_if_presigned(ctx, instance_id, &instance_parameters, &committee_pubkeys)
        .await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_nonce_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    pub_nonce: &musig2::PubNonce,
    nonce_sig: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmNonce",
    )
    .await?
    {
        return Ok(());
    }
    // 1. check pub_nonce
    if !verify_public_nonce(nonce_sig, pub_nonce, &XOnlyPublicKey::from(*received_committee_pubkey))
    {
        tracing::warn!(
            "Ignore PeginConfirmNonce for {instance_id} from {}: invalid pub_nonce or nonce_sig",
            received_committee_pubkey.to_string()
        );
        return Ok(());
    }
    // 2. save the pub_nonce to local db
    store_committee_pub_nonce_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        pub_nonce.clone(),
    )
    .await?;
    if ctx.id == GOATMessage::default_message_id() {
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, content.clone())).await?;
    }
    // 3. Agree on the full nonce transcript before generating a partial signature.
    maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_nonce_consensus_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    received_consensus_hash: [u8; 32],
    signature: &secp256k1::schnorr::Signature,
    content: &GOATMessageContent,
) -> Result<()> {
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmNonceConsensus",
    )
    .await?
    {
        return Ok(());
    }
    let message = make_message(ctx, content);
    let Some((_, _, _, _, expected_consensus_hash)) =
        pegin_confirm_nonce_consensus_context(ctx, instance_id).await?
    else {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces before validating PeginConfirm nonce consensus",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmNonceConsensus for {instance_id}: waiting for committee pub nonces"
        );
        return Ok(());
    };
    if received_consensus_hash != expected_consensus_hash {
        tracing::warn!(
            "Ignore PeginConfirmNonceConsensus for {instance_id} from {}: consensus hash mismatch",
            received_committee_pubkey
        );
        return Ok(());
    }
    if SECP256K1
        .verify_schnorr(
            signature,
            &SecpMessage::from_digest(expected_consensus_hash),
            &XOnlyPublicKey::from(*received_committee_pubkey),
        )
        .is_err()
    {
        tracing::warn!(
            "Ignore PeginConfirmNonceConsensus for {instance_id} from {}: invalid signature",
            received_committee_pubkey
        );
        return Ok(());
    }
    store_committee_agg_nonce_consensus_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        received_consensus_hash,
        *signature,
    )
    .await?;
    maybe_vote_and_sign_pegin_confirm(ctx, instance_id).await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_pegin_confirm_partial_sig_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    received_committee_pubkey: &PublicKey,
    partial_sig: &musig2::PartialSignature,
    endorse_sig: &[u8],
    content: &GOATMessageContent,
) -> Result<()> {
    // received from Committee members
    if !ensure_self_or_valid_committee(
        ctx,
        instance_id,
        None,
        received_committee_pubkey,
        "PeginConfirmPartialSig",
    )
    .await?
    {
        return Ok(());
    }
    let message = make_message(ctx, content);
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pub_nonces_unchecked =
        get_committee_pub_nonces_for_instance(ctx.local_db, instance_id).await?;
    if pub_nonces_unchecked.len() != committee_pubkeys.len() {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &message,
            30,
            MessageDeferReason::CommitteeNoncesPending,
            "waiting for committee public nonces",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmPartialSig for {instance_id}: waiting for committee pub nonces"
        );
        return Ok(());
    }
    let received_pub_nonce = match pub_nonces_unchecked
        .iter()
        .find(|(pubkey, _)| pubkey == received_committee_pubkey)
        .map(|(_, pub_nonce)| pub_nonce.clone())
    {
        Some(pub_nonce) => pub_nonce,
        None => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: missing signer pub nonce",
                received_committee_pubkey
            );
            return Ok(());
        }
    };
    let pub_nonces = match order_committee_values(
        &committee_pubkeys,
        pub_nonces_unchecked,
        "pegin committee pub nonces",
    ) {
        Ok(pub_nonces) => pub_nonces,
        Err(e) => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid pub nonce set: {e}",
                received_committee_pubkey
            );
            return Ok(());
        }
    };
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let instance_params = get_instance_parameters(ctx.local_db, instance_id)
        .await?
        .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
    let consensus_hash =
        pegin_confirm_nonce_consensus_hash(&instance_params, &committee_pubkeys, &pub_nonces)?;
    if !has_complete_pegin_confirm_nonce_consensus(
        ctx,
        instance_id,
        &committee_pubkeys,
        consensus_hash,
    )
    .await?
    {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &message,
            30,
            MessageDeferReason::CommitteeNonceConsensusPending,
            "waiting for committee PeginConfirm agg nonce consensus",
        )
        .await?;
        tracing::info!(
            "Defer PeginConfirmPartialSig for {instance_id}: waiting for agg nonce consensus"
        );
        return Ok(());
    }
    if let Err(e) = verify_pegin_confirm_partial_sig(
        &instance_params,
        &committee_pubkeys,
        received_committee_pubkey,
        &received_pub_nonce,
        &agg_nonce,
        *partial_sig,
    ) {
        tracing::warn!(
            "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid partial signature: {e}",
            received_committee_pubkey
        );
        return Ok(());
    }
    let pegin_confirm = instance_params.build_pegin_tx()?.1;
    let pegin_txid = pegin_confirm.tx().compute_txid();
    match verify_pegin_endorsement(
        ctx.goat_client,
        instance_id,
        received_committee_pubkey,
        &pegin_txid,
        endorse_sig,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "Ignore PeginConfirmPartialSig for {instance_id} from {}: invalid endorsement signature",
                received_committee_pubkey
            );
            return Ok(());
        }
        Err(e) => {
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                instance_id,
                &message,
                30,
                MessageDeferReason::ValidationRetry,
                &format!("failed to verify committee endorsement signature: {e}"),
            )
            .await?;
            tracing::warn!(
                "Retry PeginConfirmPartialSig later for {instance_id} from {}: failed to verify endorsement signature: {e}",
                received_committee_pubkey
            );
            return Ok(());
        }
    }
    // 1. save the validated partial signature & endorsement signature to local db
    store_committee_partial_sig_for_instance(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        *partial_sig,
    )
    .await?;
    store_committee_endorse_sig_for_pegin(
        ctx.local_db,
        instance_id,
        *received_committee_pubkey,
        endorse_sig.to_owned(),
    )
    .await?;
    if ctx.id == GOATMessage::default_message_id() {
        send_to_peer(ctx.swarm, GOATMessage::new(Actor::Committee, content.clone())).await?;
    }
    broadcast_pegin_confirm_if_presigned(ctx, instance_id, &instance_params, &committee_pubkeys)
        .await
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id))]
async fn handle_post_ready(ctx: &mut HandlerContext<'_>, instance_id: Uuid) -> Result<()> {
    // triggered by PeginConfirm tx
    if !is_relayer() {
        return Ok(());
    }
    // 1. (Relayer)call Gateway.postPeginData on GoatChain
    let committee_pubkeys = ctx.goat_client.gateway_get_committee_pubkeys(&instance_id).await?;
    let pegin_data = ctx.goat_client.gateway_get_pegin_data(&instance_id).await?;
    if pegin_data.status == PeginStatus::None {
        tracing::warn!("Ignore PostReady for {instance_id}: not a pending pegin request");
        return Ok(());
    } else if pegin_data.status == PeginStatus::Pending {
        let instance_params = get_instance_parameters(ctx.local_db, instance_id)
            .await?
            .ok_or_else(|| anyhow!("Instance parameters not found for {instance_id}"))?;
        let pegin_confirm = instance_params.build_pegin_tx()?.1;
        let pegin_txid = pegin_confirm.tx().compute_txid();
        let pegin_tx = match ctx.btc_client.get_tx(&pegin_txid).await? {
            Some(tx) => tx,
            None => {
                let delay_secs = avg_block_time_secs(ctx.btc_client.network());
                let message = GOATMessage::new(
                    ctx.actor.clone(),
                    GOATMessageContent::PostReady(PostReady { instance_id }),
                );
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    instance_id,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::BitcoinTransactionPending,
                    "pegin-confirm transaction is not available from the Bitcoin backend",
                )
                .await?;
                tracing::warn!(
                    "Retry postPeginData later for {instance_id}: Pegin-Confirm transaction not found on Bitcoin: {pegin_txid}"
                );
                return Ok(());
            }
        };
        let endorse_sigs = get_committee_endorse_sigs_for_pegin(ctx.local_db, instance_id)
            .await?
            .into_iter()
            .map(|(_, es)| es)
            .collect::<Vec<_>>();
        if endorse_sigs.len() != committee_pubkeys.len() {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = GOATMessage::new(
                ctx.actor.clone(),
                GOATMessageContent::PostReady(PostReady { instance_id }),
            );
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                instance_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::CommitteeEndorsementsPending,
                "waiting for all committee endorsements of the pegin-confirm transaction",
            )
            .await?;
            tracing::warn!(
                "Retry postPeginData later for {instance_id}: not enough endorse sigs for pegin confirm tx: {}",
                endorse_sigs.len()
            );
            return Ok(());
        }
        let pegin_height = match ctx.btc_client.get_tx_status(&pegin_txid).await?.block_height {
            Some(height) => height as u64,
            None => {
                let delay_secs = avg_block_time_secs(ctx.btc_client.network());
                let message = GOATMessage::new(
                    ctx.actor.clone(),
                    GOATMessageContent::PostReady(PostReady { instance_id }),
                );
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    instance_id,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::BitcoinConfirmationPending,
                    "pegin-confirm transaction is not confirmed on Bitcoin",
                )
                .await?;
                tracing::info!(
                    "Retry postPeginData later for {instance_id}: pegin confirm tx not confirmed on btc yet"
                );
                return Ok(());
            }
        };
        let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
        if goat_confirmed_height < pegin_height {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network())
                * (pegin_height - goat_confirmed_height);
            let message = GOATMessage::new(
                ctx.actor.clone(),
                GOATMessageContent::PostReady(PostReady { instance_id }),
            );
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                instance_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::GoatSpvPending,
                "pegin-confirm block is not available through GOAT SPV",
            )
            .await?;
            tracing::info!(
                "Retry postPeginData later for {instance_id}: pegin confirm tx block not posted to goat spv contract yet"
            );
            return Ok(());
        }
        let result = ctx
            .goat_client
            .gateway_post_pegin_data(ctx.btc_client, &instance_id, &pegin_tx, &endorse_sigs)
            .await;
        ctx.metrics_state.record_pegin_post(result.is_ok());
        result?;
    } else {
        // already posted
    }
    // 2. (Relayer)call Gateway.postGraphData on GoatChain
    let graph_ids = get_graph_ids_for_instance(ctx.local_db, instance_id).await?;
    let mut missing_graph_endorsements = false;
    for graph_id in &graph_ids {
        let graph_data = ctx.goat_client.gateway_get_graph_data(graph_id).await?;
        if graph_data.operator_pubkey != [0u8; 32] {
            // already posted
            continue;
        }
        let endorsement_sigs =
            get_committee_endorsements_for_graph(ctx.local_db, instance_id, *graph_id)
                .await?
                .into_iter()
                .map(|(_, _, sig)| sig)
                .collect::<Vec<_>>();
        if endorsement_sigs.len() != committee_pubkeys.len() {
            missing_graph_endorsements = true;
            tracing::warn!(
                "Defer postGraphData for {instance_id}:{graph_id}: not enough endorse sigs for graph: {}",
                endorsement_sigs.len()
            );
            continue;
        }
        let graph = get_graph(ctx.local_db, instance_id, *graph_id)
            .await?
            .ok_or_else(|| anyhow!("Graph not found for {instance_id}:{graph_id}"))?;
        let graph = BitvmGcGraph::from_simplified(&graph)?;
        let graph_data = build_graph_data(&graph)?;
        ctx.goat_client
            .gateway_post_graph_data(&instance_id, graph_id, &graph_data, &endorsement_sigs)
            .await?;
    }
    if missing_graph_endorsements {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network());
        let message = GOATMessage::new(
            ctx.actor.clone(),
            GOATMessageContent::PostReady(PostReady { instance_id }),
        );
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            instance_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::CommitteeEndorsementsPending,
            "waiting for committee graph endorsements",
        )
        .await?;
        tracing::info!(
            "Retry postGraphData later for {instance_id}: waiting for committee graph endorsements"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by InitWithdraw event from GoatChain
    let message = make_message(ctx, content);
    let graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        instance_id,
        graph_id,
        &message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(()),
    };
    let mut graph = BitvmGcGraph::from_simplified(&graph)?;
    let operator_pubkey = graph.parameters.operator_pubkey;
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let node_pubkey: PublicKey = operator_master_key.master_keypair().public_key().into();
    if node_pubkey != operator_pubkey {
        tracing::warn!("Ignore KickoffReady for {instance_id}:{graph_id}: not my graph");
        return Ok(());
    }
    // 1. check the withdraw status on GoatChain
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffReady for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    // 2. check prekickoff nonce & broadcast previous pre-kickoff if needed
    let start_nonce =
        match get_latest_pegout_finalized_graph(ctx.local_db, &operator_pubkey).await? {
            Some((n, _)) => n + 1,
            None => 0,
        };
    for current_nonce in start_nonce..graph.parameters.graph_nonce {
        let (current_instance_id, current_graph_id) = match get_graph_id_by_nonce(
            ctx.local_db,
            current_nonce,
            &operator_pubkey,
        )
        .await?
        {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: missing previous graph {current_nonce}"
                );
                return Ok(());
            }
        };
        let current_graph = match get_graph_or_defer(
            ctx.swarm,
            ctx.local_db,
            ctx.goat_client,
            current_instance_id,
            current_graph_id,
            &message,
        )
        .await?
        {
            Some(g) => g,
            None => return Ok(()),
        };
        let mut current_graph = BitvmGcGraph::from_simplified(&current_graph)?;
        let current_graph_refresh = refresh_graph(
            ctx.local_db,
            ctx.btc_client,
            ctx.goat_client,
            current_instance_id,
            current_graph_id,
            &current_graph,
        )
        .await?;
        let current_graph_status = current_graph_refresh.status;
        if current_graph_refresh.status_transition_accepted {
            compensate_graph_events(
                ctx.local_db,
                ctx.btc_client,
                current_instance_id,
                current_graph_id,
                &current_graph,
                current_graph_refresh.scan.as_ref(),
                // This is a recovery scan, not a transition from the local
                // projection. Start from the protocol baseline so a previous
                // crash between status persistence and message enqueue can be
                // repaired by idempotent message upserts.
                GraphStatus::OperatorPresigned,
                current_graph_status,
            )
            .await?;
        }
        if current_graph_status.is_closed() {
            continue;
        } else if current_graph_status.is_pegout_started() {
            tracing::warn!(
                "Ignore KickoffReady for {instance_id}:{graph_id}: previous graph {current_graph_id} already started pegout"
            );
            let nonce_interval =
                graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
            let min_pegout_time_secs = take1_timelock_with_config(
                ctx.btc_client.network(),
                &current_graph.parameters.timelock_config,
            ) as u64
                * avg_block_time_secs(ctx.btc_client.network());
            let delay_secs = min_pegout_time_secs * nonce_interval;
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::PreviousGraphPending,
                "previous graph has an active pegout flow",
            )
            .await?;
            return Ok(());
        } else if current_graph_status.is_obsoleted() {
            operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
            tracing::info!(
                "Operator {operator_pubkey} skipped obsoleted graph {current_instance_id}:{current_graph_id}"
            );
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::ChainStatePending,
                "waiting for the previous obsoleted graph skip transaction to propagate",
            )
            .await?;
            return Ok(());
        } else {
            let graph_data_on_goat =
                ctx.goat_client.gateway_get_graph_data(&current_graph_id).await?;
            if graph_data_on_goat.operator_pubkey != [0u8; 32] {
                tracing::warn!(
                    "Ignore KickoffReady for {instance_id}:{graph_id}: previous available graph exists for Operator {operator_pubkey}: {current_instance_id}:{current_graph_id}, please withdraw it first"
                );
                let nonce_interval =
                    graph.parameters.graph_nonce - current_graph.parameters.graph_nonce;
                let min_pegout_time_secs = take1_timelock_with_config(
                    ctx.btc_client.network(),
                    &current_graph.parameters.timelock_config,
                ) as u64
                    * avg_block_time_secs(ctx.btc_client.network());
                let delay_secs = min_pegout_time_secs * nonce_interval;
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    graph_id,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::PreviousGraphPending,
                    "previous graph is available for pegout",
                )
                .await?;
                return Ok(());
            } else {
                operator_skip_graph(ctx.btc_client, &mut current_graph).await?;
                tracing::info!(
                    "Operator {operator_pubkey} skipped non-posted graph {current_instance_id}:{current_graph_id}"
                );
                let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 blocks
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    graph_id,
                    &message,
                    delay_secs as usize,
                    MessageDeferReason::ChainStatePending,
                    "waiting for the previous graph skip transaction to propagate",
                )
                .await?;
                return Ok(());
            }
        }
    }
    // 3. sign & broadcast prekickoff & kickoff txns
    operator_kickoff(ctx.btc_client, &mut graph).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    // 1. update status
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorKickOff)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) try to call Gateway.proceedWithdraw
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status != WithdrawStatus::Initialized {
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_tx = match ctx.btc_client.get_tx(&kickoff_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not found on chain: {kickoff_txid}"
            );
            return Ok(());
        }
    };
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "kickoff transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_btc_height < kickoff_height {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network())
            * (kickoff_height - goat_confirmed_btc_height);
        let message = make_message(ctx, content);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "kickoff block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry proceedWithdraw later for {instance_id}:{graph_id}: kickoff tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client.gateway_process_withdraw(ctx.btc_client, &graph_id, &kickoff_tx).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check kickoff tx status on Bitcoin chain
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore KickoffSent for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
            );
            return Ok(());
        }
    };
    handle_previous_graph_after_prekickoff(ctx, instance_id, graph_id, &graph, &message).await?;
    let take1_txid = graph.take1.tx().compute_txid();
    let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
    let kickoff_challenge_outpoint = challenge_tx.input[0].previous_output;
    if let Some(spent_txid) = outpoint_spent_txid(
        ctx.btc_client,
        &kickoff_challenge_outpoint.txid,
        kickoff_challenge_outpoint.vout as u64,
    )
    .await?
    {
        let spent_tx_name = if spent_txid == take1_txid { "Take1" } else { "Challenge" };
        tracing::warn!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: challenge connector already spent by {spent_tx_name} tx: {spent_txid}"
        );
        return Ok(());
    }
    // 2. check withdraw status, if it's invalid, sign & broadcast challenge txn
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    let goat_confirmed_btc_height = ctx.goat_client.btc_spv_latest_height().await? as u32;
    if [WithdrawStatus::None, WithdrawStatus::Canceled].contains(&withdraw_status) {
        if kickoff_height >= goat_confirmed_btc_height {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network())
                * (kickoff_height - goat_confirmed_btc_height) as u64;
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::GoatSpvPending,
                "kickoff block is not available through GOAT SPV",
            )
            .await?;
            tracing::info!(
                "Retry Challenge later for {instance_id}:{graph_id}: kickoff tx block is not posted to GOAT SPV yet"
            );
            return Ok(());
        }

        let (challenge_tx, _) = export_challenge_tx(&graph).unwrap();
        let challenge_txid = challenge_tx.compute_txid();
        if ctx.btc_client.get_tx(&challenge_txid).await?.is_none() {
            send_challenge_tx(ctx.btc_client, &graph).await?;
        }
    } else {
        tracing::info!(
            "Ignore KickoffSent for {instance_id}:{graph_id}: withdraw already initiated, status: {withdraw_status:?}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_kickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Kickoff tx
    let message = make_message(ctx, content);
    let _graph = refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?;
    Ok(())
}

async fn handle_previous_graph_after_prekickoff(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
    message: &GOATMessage,
) -> Result<()> {
    if !tx_on_chain(
        ctx.btc_client,
        &graph.parameters.prekickoff_parameters.cur_prekickoff_txn.tx().compute_txid(),
    )
    .await?
    {
        tracing::warn!(
            "Ignore prekickoff follow-up for {instance_id}:{graph_id}: prekickoff tx not on chain"
        );
        return Ok(());
    }

    let graph_nonce = graph.parameters.graph_nonce;
    if graph_nonce == 0 {
        return Ok(());
    }

    let (prev_instance_id, prev_graph_id) =
        get_graph_id_by_nonce(ctx.local_db, graph_nonce - 1, &graph.parameters.operator_pubkey)
            .await?
            .ok_or_else(|| anyhow!("Prev graph not found for {instance_id}:{graph_id}"))?;
    let prev_graph = match get_graph_or_defer(
        ctx.swarm,
        ctx.local_db,
        ctx.goat_client,
        prev_instance_id,
        prev_graph_id,
        message,
    )
    .await?
    {
        Some(g) => g,
        None => return Ok(()),
    };
    let prev_graph = BitvmGcGraph::from_simplified(&prev_graph)?;
    let (prev_graph_status, _prev_graph_sub_status, status_transition_accepted) =
        refresh_and_compensate(
            ctx,
            prev_instance_id,
            prev_graph_id,
            &prev_graph,
            // Do not use the persisted status as a compensation anchor: it
            // may have been committed just before a crash. Idempotent message
            // upserts make a baseline recovery scan safe to retry.
            GraphStatus::OperatorPresigned,
        )
        .await?;
    if !status_transition_accepted {
        tracing::warn!(
            "Ignore prekickoff follow-up for {instance_id}:{graph_id}: previous graph status scan was rejected"
        );
        return Ok(());
    }
    if !tx_on_chain(ctx.btc_client, &prev_graph.kickoff.tx().compute_txid()).await? {
        verifier_force_skip_kickoff(ctx.btc_client, &prev_graph).await?;
    } else if !prev_graph_status.is_closed() {
        verifier_quick_challenge(ctx.btc_client, &prev_graph).await?;
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by PreKickoff tx
    let message = make_message(ctx, content);
    let graph = match get_graph_for_refresh_or_defer(ctx, instance_id, graph_id, &message).await? {
        Some(graph) => graph,
        None => return Ok(()),
    };

    let (_, _, status_transition_accepted) =
        refresh_and_compensate(ctx, instance_id, graph_id, &graph, GraphStatus::PreKickoff).await?;
    if !status_transition_accepted {
        // PreKickoffSent may arrive after KickoffSent or an event-watcher
        // update. The state transition is then correctly rejected as stale,
        // but the confirmed pre-kickoff still proves that the previous graph
        // must be reconciled.
        tracing::info!(
            event = "prekickoff_reconciliation",
            outcome = "current_status_stale",
            "reconciling previous graph despite stale PreKickoff transition"
        );
    }

    // Check the previous graph independently from whether this graph could
    // still transition to PreKickoff. The helper revalidates the on-chain
    // pre-kickoff transaction before it can broadcast any disprove action.
    handle_previous_graph_after_prekickoff(ctx, instance_id, graph_id, &graph, &message).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_prekickoff_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by PreKickoff tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::PreKickoff).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Challenge tx
    let message = make_message(ctx, content);
    let (mut graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    // 1. check the challenge tx status on Bitcoin chain
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: watchtower challenge init already sent"
        );
        return Ok(());
    }
    if let Some(challenge_tx) = ctx.btc_client.get_tx(&challenge_txid).await? {
        let challenge_outpoint = graph
            .kickoff
            .connector_a_input()
            .map_err(|e| anyhow!("failed to get connector-a input: {e}"))?
            .outpoint;
        if challenge_tx.input[0].previous_output != challenge_outpoint {
            tracing::warn!(
                "Ignore ChallengeSent for {instance_id}:{graph_id}: invalid challenge tx input"
            );
            return Ok(());
        }
    } else {
        tracing::warn!(
            "Ignore ChallengeSent for {instance_id}:{graph_id}: challenge tx not found on chain"
        );
        return Ok(());
    }
    // 2. if the challenge is confirmed, sign & broadcast watchtower-challenge-init txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let watchtower_challenge_init_tx =
        operator_sign_watchtower_challenge_init(operator_master_key.master_keypair(), &mut graph)?;
    let anchor_vout = watchtower_challenge_init_tx.output.len() as u64 - 1;
    let watchtower_challenge_init_tx_total_input_amount =
        graph.watchtower_challenge_init.prev_outs().iter().map(|o| o.value).sum();
    let child_tx = build_cpfp_txns(
        ctx.btc_client,
        &watchtower_challenge_init_tx,
        anchor_vout,
        watchtower_challenge_init_tx_total_input_amount,
    )
    .await?;
    match child_tx {
        Some(tx) => {
            broadcast_package(ctx.btc_client, &[watchtower_challenge_init_tx, tx], true).await?
        }
        None => broadcast_tx(ctx.btc_client, &watchtower_challenge_init_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Challenge tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_init_sent_watchtower(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by WatchtowerChallengeInit tx
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_keypair = WatchtowerMasterKey::new(get_bitvm_key()?).master_keypair();
    let node_index = match graph
        .parameters
        .watchtower_pubkeys
        .iter()
        .position(|pk| *pk == watchtower_keypair.public_key().x_only_public_key().0)
    {
        Some(index) => index,
        None => {
            tracing::warn!(
                "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: node not a watchtower"
            );
            return Ok(());
        }
    };
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    if !tx_on_chain(ctx.btc_client, &watchtower_challenge_init_txid).await? {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge init not on chain"
        );
        return Ok(());
    }
    let watchtower_challenge_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(node_index) as u64;
    if outpoint_spent_txid(
        ctx.btc_client,
        &watchtower_challenge_init_txid,
        watchtower_challenge_vout,
    )
    .await?
    .is_some()
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: watchtower challenge already spent"
        );
        return Ok(());
    }
    // watchtower should always challenge
    let watchtower_proof = match get_watchtower_commitment(
        ctx.local_db,
        ctx.btc_client,
        ctx.http_client,
        instance_id,
        graph_id,
    )
    .await?
    {
        (Some(p), _) => p,
        (None, wait_secs) => {
            tracing::warn!(
                "Retry WatchtowerChallengeInitSent for {instance_id}:{graph_id} later: watchtower proof not ready, retry after {wait_secs} seconds"
            );
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                wait_secs,
                MessageDeferReason::ProofPending,
                "watchtower proof commitment is not ready",
            )
            .await?;
            return Ok(());
        }
    };
    let watchtower_challenge_txid = match send_watchtower_challenge_tx(
        ctx.btc_client,
        &graph,
        node_index,
        watchtower_proof,
    )
    .await
    {
        Ok(txid) => txid,
        Err(e) => {
            tracing::warn!(
                "Ignore WatchtowerChallengeInitSent for {instance_id}:{graph_id}: failed to send watchtower challenge tx: {e}"
            );
            return Ok(());
        }
    };
    tracing::info!(
        "WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower_index={node_index}, txid={watchtower_challenge_txid}"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id, watchtower_index = watchtower_index))]
async fn handle_watchtower_challenge_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    watchtower_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;
    if watchtower_index >= watchtower_num {
        bail!("watchtower index {watchtower_index} out of range for {watchtower_num} slots");
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_vout =
        output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index) as u64;
    let Some((watchtower_spent_txid, watchtower_vin, _txin)) =
        outpoint_spent_txin(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
    else {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} is not spent yet"
        );
        return Ok(());
    };
    if watchtower_vin != 0 {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by tx {watchtower_spent_txid} at unexpected input index {watchtower_vin}"
        );
        return Ok(());
    }
    let timeout_txid = graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
    if watchtower_spent_txid == timeout_txid {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: watchtower connector {watchtower_index} was spent by timeout tx {timeout_txid}"
        );
        return Ok(());
    }

    let ack_vout =
        output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
    if let Some(spent_txid) =
        outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout).await?
    {
        tracing::warn!(
            "Ignore WatchtowerChallengeSent for {instance_id}:{graph_id}: ack connector {watchtower_index} already spent by {spent_txid}"
        );
        return Ok(());
    }

    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let preimage = operator_master_key.preimage_for_graph(graph_id, watchtower_index);
    let ack_connector_input = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|e| anyhow!("failed to get ack connector input: {e}"))?;
    let ack_input = operator_sign_challenge_ack(&graph, watchtower_index, &preimage)?;
    let ack_txid = build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_master_key.master_keypair(),
        vec![ack_input],
        ack_connector_input.amount,
        vec![goat::scripts::p2a_output()],
    )
    .await?;
    tracing::info!(
        "Operator challenge ACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={ack_txid}"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_watchtower_challenge_timeout_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore WatchtowerChallengeTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }

    let watchtower_num = validate_watchtower_branches(&graph)?;
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
            .await?
            .is_some()
            || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
                .await?
                .is_some()
        {
            continue;
        }

        let timeout_tx = operator_sign_watchtower_challenge_timeout(
            operator_master_key.master_keypair(),
            &mut graph,
            watchtower_index,
        )?;
        if tx_on_chain(ctx.btc_client, &timeout_tx.compute_txid()).await? {
            continue;
        }
        let timeout_txid = timeout_tx.compute_txid();
        let timeout_tx_total_input_amount = graph.watchtower_challenge_timeouts[watchtower_index]
            .prev_outs()
            .iter()
            .map(|o| o.value)
            .sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
        tracing::info!(
            "Watchtower challenge timeout sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={timeout_txid}"
        );
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_nack_ready_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore NackReady for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let watchtower_num = validate_watchtower_branches(&graph)?;

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
        .await?
        .is_some()
    {
        tracing::warn!("Ignore NackReady for {instance_id}:{graph_id}: connector-F already spent");
        return Ok(());
    }

    for watchtower_index in 0..watchtower_num {
        let watchtower_vout =
            output_topology::watchtower_challenge_init::watchtower_connector(watchtower_index)
                as u64;
        let Some(watchtower_spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, watchtower_vout)
                .await?
        else {
            continue;
        };

        let timeout_txid =
            graph.watchtower_challenge_timeouts[watchtower_index].tx().compute_txid();
        if watchtower_spent_txid == timeout_txid {
            continue;
        }

        let ack_vout =
            output_topology::watchtower_challenge_init::ack_connector(watchtower_index) as u64;
        if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, ack_vout)
            .await?
            .is_some()
        {
            continue;
        }

        let nack = graph
            .operator_challenge_nacks
            .get(watchtower_index)
            .ok_or_else(|| anyhow!("invalid watchtower index {watchtower_index}"))?;
        let nack_tx = nack.tx().clone();
        let nack_txid = nack_tx.compute_txid();
        if tx_on_chain(ctx.btc_client, &nack_txid).await? {
            return Ok(());
        }
        let nack_tx_total_input_amount = nack.prev_outs().iter().map(|o| o.value).sum::<Amount>();
        broadcast_tx_with_cpfp(ctx.btc_client, nack_tx, nack_tx_total_input_amount).await?;
        tracing::info!(
            "Operator challenge NACK sent for {instance_id}:{graph_id}: watchtower_index={watchtower_index}, txid={nack_txid}"
        );
        return Ok(());
    }

    tracing::warn!(
        "Ignore NackReady for {instance_id}:{graph_id}: no watchtower branch is ready for NACK"
    );
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let Some((graph, _graph_status, _graph_sub_status)) =
        refresh_graph_status(ctx, instance_id, graph_id, Some(&message), GraphStatus::Challenge)
            .await?
    else {
        return Ok(());
    };

    // compute the 96-byte guest pubin
    let watchtower_challenge_init_txid =
        SerializableTxid::from(graph.watchtower_challenge_init.tx().compute_txid());
    let num_watchtowers = graph.parameters.watchtower_pubkeys.len();
    let watchtower_timeout_txids: Vec<Txid> =
        graph.watchtower_challenge_timeouts.iter().map(|tx| tx.tx().compute_txid()).collect();
    let wait_secs = avg_block_time_secs(ctx.btc_client.network()) as usize;
    let WatchtowerChallengeInfo {
        included_watchtowers: included_watchtowers_bits,
        resolved_branch_txids,
        ..
    } = match get_watchtower_challenge_info(
        ctx.btc_client,
        &watchtower_challenge_init_txid,
        &watchtower_timeout_txids,
        num_watchtowers,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::info!(
                "Retry OperatorCommitPubinReady later for {instance_id}:{graph_id}: challenge info is not ready: {e}"
            );
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                wait_secs,
                MessageDeferReason::ProtocolInputsPending,
                "watchtower challenge branches are not resolved yet",
            )
            .await?;
            return Ok(());
        }
    };
    let (btc_best_block_hash, included_watchtowers_bitmap) =
        match compute_operator_pubin_blockhash_and_bitmap(
            ctx.btc_client,
            &resolved_branch_txids,
            &included_watchtowers_bits,
        )
        .await
        {
            Ok(inputs) => inputs,
            Err(e) => {
                tracing::info!(
                    "Retry OperatorCommitPubinReady later for {instance_id}:{graph_id}: operator pubin inputs are not ready: {e}"
                );
                push_local_unhandled_messages_with_reason(
                    ctx.local_db,
                    graph_id,
                    &message,
                    wait_secs,
                    MessageDeferReason::ProtocolInputsPending,
                    &e.to_string(),
                )
                .await?;
                return Ok(());
            }
        };
    let guest_pubin = build_operator_guest_pubin(
        &btc_best_block_hash,
        &graph.parameters.pubin_disprove_constant,
        &included_watchtowers_bitmap,
    );

    // sign and broadcast
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let commit_pubin_wots_sk = operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id).0;
    let signed_input = operator_sign_commit_pubin(&graph, &commit_pubin_wots_sk, &guest_pubin)?;
    let connector_e_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow!("failed to get connector-e input: {e}"))?
        .amount;
    let operator_keypair = operator_master_key.master_keypair();
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_keypair,
        vec![signed_input],
        connector_e_amount,
        vec![],
    )
    .await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_operator_commit_pubin_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    let message = make_message(ctx, content);
    let (graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }

    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let connector_e_vout =
        output_topology::watchtower_challenge_init::connector_e(watchtower_num) as u64;
    let connector_f_vout =
        output_topology::watchtower_challenge_init::connector_f(watchtower_num) as u64;
    if outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_e_vout)
        .await?
        .is_some()
        || outpoint_spent_txid(ctx.btc_client, &watchtower_challenge_init_txid, connector_f_vout)
            .await?
            .is_some()
    {
        tracing::warn!(
            "Ignore OperatorCommitPubinTimeout for {instance_id}:{graph_id}: timeout input already spent"
        );
        return Ok(());
    }

    let timeout_tx = graph.operator_commit_timeout.tx().clone();
    let timeout_txid = timeout_tx.compute_txid();
    if tx_on_chain(ctx.btc_client, &timeout_txid).await? {
        return Ok(());
    }
    let timeout_tx_total_input_amount =
        graph.operator_commit_timeout.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, timeout_tx, timeout_tx_total_input_amount).await?;
    tracing::info!(
        "Operator commit pubin timeout sent for {instance_id}:{graph_id}: txid={timeout_txid}"
    );
    Ok(())
}

// after the watchtower challenge flow is complete, build proof and broadcast Assert transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    let message = GOATMessage::new(
        Actor::Operator,
        GOATMessageContent::AssertReady(AssertReady { instance_id, graph_id }),
    );
    let (mut graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    let (operator_proof, wait_secs) = get_operator_proof(
        ctx.local_db,
        ctx.http_client,
        &graph,
        ctx.btc_client,
        instance_id,
        graph_id,
    )
    .await?;

    if wait_secs > 0 {
        tracing::info!(
            "Retry AssertReady later for {instance_id}:{graph_id}: operator proof is not ready"
        );
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            wait_secs,
            MessageDeferReason::ProofPending,
            "operator proof is not ready",
        )
        .await?;
        return Ok(());
    }

    let Some(operator_proof) = operator_proof else {
        return Ok(());
    };
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let assert_secret_key = operator_master_key.assert_wots_keypair_for_graph(graph_id).0;

    let dynamic_input = operator_assert_dynamic_input(&operator_proof.public_inputs)?;
    let assert_witness =
        build_assert_witness(&operator_proof.proof, &assert_secret_key, dynamic_input)?;
    let assert_message = assert_wots_message(&assert_witness)?;
    let mut asserted_operator_proof = Vec::new();
    operator_proof.proof.serialize_compressed(&mut asserted_operator_proof)?;
    let mut setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .as_mut()
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    if let Some(existing) = &operator_state.asserted_operator_proof
        && existing != &asserted_operator_proof
    {
        bail!("operator assertion proof conflicts with persisted proof");
    }
    operator_state.asserted_operator_proof = Some(asserted_operator_proof);
    save_babe_setup_state(ctx.local_db, instance_id, graph_id, &setup_state)?;

    let assert_tx = operator_sign_assert(
        &mut graph,
        &assert_secret_key,
        &assert_message,
        &assert_witness.pi2,
        &assert_witness.pi3,
    )?;
    let assert_tx_total_input_amount =
        graph.operator_assert.prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, assert_tx, assert_tx_total_input_amount).await?;

    Ok(())
}

/// Recovers a `BabeChallengeAssertWitness` from the on-chain challenge assert tx.
fn recover_challenge_assert_witness(
    challenge_assert_tx: &bitcoin::Transaction,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    let txin = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("challenge assert tx has no input"))?;
    let items: Vec<Vec<u8>> = txin.witness.to_vec();
    let expected_len = 2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM + 2;
    if items.len() != expected_len {
        bail!(
            "unexpected challenge assert witness length: {} (expected {expected_len})",
            items.len()
        );
    }
    let mut bitcoin_witness = bitcoin::Witness::new();
    for item in &items[..2 * WOTS_SIG_COUNT] {
        bitcoin_witness.push(item);
    }
    let wots_sig = Wots96::raw_witness_to_signature(&bitcoin_witness).to_vec();
    let input_labels: Vec<[u8; 16]> = items
        [2 * WOTS_SIG_COUNT..2 * WOTS_SIG_COUNT + goat::assert_scripts::INPUT_WIRE_NUM]
        .iter()
        .map(|item| item.as_slice().try_into())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow!("challenge assert label item is not 16 bytes"))?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        witness: ChallengeAssertWitnessRaw { input_labels, wots_sig },
    })
}

/// Collects the on-chain ACK TxIns from all watchtowers that submitted a challenge_ack.
/// Unspent ACK connectors are skipped; spent connectors must resolve to the spending input.
async fn collect_ack_txins(
    btc_client: &BTCClient,
    wci_txid: &Txid,
    watchtower_timeout_txids: &[Txid],
) -> Result<Vec<bitcoin::TxIn>> {
    let mut ack_txins = Vec::new();
    for (i, timeout_txid) in watchtower_timeout_txids.iter().enumerate() {
        let ack_vout = output_topology::watchtower_challenge_init::ack_connector(i) as u64;
        let Some(ack_spent_txid) = outpoint_spent_txid(btc_client, wci_txid, ack_vout).await?
        else {
            continue;
        };
        if &ack_spent_txid == timeout_txid {
            continue;
        }
        let Some((_spent_txid, _vin, txin)) =
            outpoint_spent_txin(btc_client, wci_txid, ack_vout).await?
        else {
            bail!("ACK spending tx {ack_spent_txid} for watchtower {i} is unavailable");
        };
        ack_txins.push(txin);
    }
    Ok(ack_txins)
}

// verify Operator DynamicPublicInput and Proof; broadcast PubinDisprove or ChallengeAssert as needed.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_assert_sent_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };

    let Some(assert_tx) = ctx.btc_client.get_tx(&assert_txid).await? else {
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: assert tx {assert_txid} not found on chain"
        );
        return Ok(());
    };

    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(());
    };
    validate_verifier_slot(&graph, verifier_index)?;

    // ChallengeAssert may only be skipped after this graph's commit-pubin is
    // on-chain and proves consistent with the assert witness. OperatorAssert
    // can otherwise be broadcast before connector-E is spent.
    let connector_e_input = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|error| anyhow!("failed to resolve connector-E input: {error}"))?;
    let connector_e_outpoint = connector_e_input.outpoint;
    let Some(connector_e_spent_txid) = outpoint_spent_txid(
        ctx.btc_client,
        &connector_e_outpoint.txid,
        connector_e_outpoint.vout as u64,
    )
    .await?
    else {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network());
        let message = make_message(ctx, content);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::ProtocolInputsPending,
            "operator commit-pubin is not on chain yet",
        )
        .await?;
        tracing::info!(
            "Retry AssertSent later for {instance_id}:{graph_id}: operator commit-pubin is not on chain yet"
        );
        return Ok(());
    };

    let mut pubin_consistent = false;
    if connector_e_spent_txid != graph.operator_commit_timeout.tx().compute_txid() {
        if !ctx.btc_client.get_tx_status(&connector_e_spent_txid).await?.confirmed {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::ProtocolInputsPending,
                "operator commit-pubin transaction is not confirmed yet",
            )
            .await?;
            return Ok(());
        }
        let Some(commit_pubin_tx) = ctx.btc_client.get_tx(&connector_e_spent_txid).await? else {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            let message = make_message(ctx, content);
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::ProtocolInputsPending,
                "operator commit-pubin transaction is not available yet",
            )
            .await?;
            return Ok(());
        };
        let assert_txin = assert_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
        let commit_pubin_txin = commit_pubin_tx
            .input
            .first()
            .ok_or_else(|| anyhow!("operator commit-pubin transaction has no input"))?;
        let wci_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let watchtower_timeout_txids = graph
            .watchtower_challenge_timeouts
            .iter()
            .map(|tx| tx.tx().compute_txid())
            .collect::<Vec<_>>();
        let ack_txins =
            match collect_ack_txins(ctx.btc_client, &wci_txid, &watchtower_timeout_txids).await {
                Ok(txins) => txins,
                Err(error) => {
                    let delay_secs = avg_block_time_secs(ctx.btc_client.network());
                    let message = make_message(ctx, content);
                    push_local_unhandled_messages_with_reason(
                        ctx.local_db,
                        graph_id,
                        &message,
                        delay_secs as usize,
                        MessageDeferReason::ProtocolInputsPending,
                        &format!("operator ACK inputs are not ready: {error}"),
                    )
                    .await?;
                    return Ok(());
                }
            };
        match validate_pubin_disprove(&graph, commit_pubin_txin, assert_txin, &ack_txins) {
            Ok(Some((witness_data, _))) => {
                // PubinDisprove is not pre-signed, so fund it directly rather
                // than relying on CPFP.
                let pubin_disprove_tx_total_input_amount = graph
                    .operator_assert
                    .connector_d_input()
                    .map_err(|e| anyhow!("failed to get connector-d input: {e}"))?
                    .amount;
                let pubin_disprove_txin = build_pubin_disprove_txin(&graph, witness_data)?;
                let pubin_disprove_tx = bitcoin::Transaction {
                    version: bitcoin::transaction::Version(2),
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![pubin_disprove_txin],
                    output: vec![
                        goat::scripts::p2a_output(),
                        // Keep the transaction above Bitcoin Core's minimum
                        // non-witness relay size.
                        bitcoin::TxOut {
                            value: Amount::ZERO,
                            script_pubkey: goat::scripts::generate_opreturn_script(
                                PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                            ),
                        },
                    ],
                };
                let verifier_keypair = VerifierMasterKey::new(get_bitvm_key()?).master_keypair();
                build_sign_and_broadcast_tx(
                    ctx.btc_client,
                    verifier_keypair,
                    pubin_disprove_tx.input,
                    pubin_disprove_tx_total_input_amount,
                    pubin_disprove_tx.output,
                )
                .await?;
                return Ok(());
            }
            Ok(None) => {
                pubin_consistent = true;
            }
            Err(error) => tracing::warn!(
                "PubinDisprove validation failed for {instance_id}:{graph_id}: {error}; proceeding to ChallengeAssert"
            ),
        }
    }

    // recover TxAssertWitness from the assert tx witness.
    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(&graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;
    if pubin_consistent && assert_witness.verify_groth16_proof(&vk, &[static_input]) {
        tracing::info!(
            "Skip ChallengeAssert for {instance_id}:{graph_id}: operator assert proof is valid"
        );
        return Ok(());
    }

    let strict = false;
    broadcast_verifier_challenge_assert_tx(
        ctx.local_db,
        ctx.btc_client,
        &graph,
        instance_id,
        graph_id,
        &assert_tx,
        strict,
    )
    .await?;

    Ok(())
}

const PUBIN_DISPROVE_OP_RETURN_DATA: &[u8] = b"pubin-disprove";

pub async fn broadcast_verifier_challenge_assert_tx(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
    instance_id: Uuid,
    graph_id: Uuid,
    assert_tx: &bitcoin::Transaction,
    strict: bool,
) -> Result<Option<(Txid, usize)>> {
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let verifier_pubkey = verifier_master_key.master_keypair().public_key().into();
    let Some(verifier_index) =
        find_verifier_index_by_pubkey(&graph.parameters.gc_data, &verifier_pubkey)?
    else {
        if strict {
            bail!("local verifier has no graph slot for {instance_id}:{graph_id}");
        }
        tracing::debug!(
            "Ignore AssertSent for {instance_id}:{graph_id}: local verifier has no graph slot"
        );
        return Ok(None);
    };
    validate_verifier_slot(graph, verifier_index)?;

    let assert_txin = assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let assert_witness = extract_operator_assert_witness_for_challenge(graph, assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let vk = crate::vk::get_vk().await.context("load Groth16 verifying key for operator assert")?;
    let static_input = derive_operator_static_input()?;

    let Some(saved_verifier_state) =
        load_babe_setup_state(local_db, instance_id, graph_id)?.and_then(|state| state.verifier)
    else {
        if strict {
            bail!("missing BABE verifier setup state for {instance_id}:{graph_id}");
        }
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: missing BABE verifier setup state"
        );
        return Ok(None);
    };
    if saved_verifier_state.soldering_proof_ready.is_none() {
        if strict {
            bail!("missing soldering proof reference for {instance_id}:{graph_id}");
        }
        tracing::warn!(
            "Ignore AssertSent for {instance_id}:{graph_id}: missing soldering proof reference"
        );
        return Ok(None);
    }
    let challenge_witness = build_real_challenge_assert_witness(
        &saved_verifier_state.private_state,
        &saved_verifier_state.setup_package,
        &saved_verifier_state.finalized_indices,
        &vk,
        static_input,
        &assert_witness,
        verifier_index,
    )?;
    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txin = assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("operator assert transaction has no input"))?;
    let challenge_assert_tx =
        build_verifier_assert_tx(graph, operator_assert_txin, verifier_index, labels)?;
    let challenge_assert_txid = challenge_assert_tx.compute_txid();
    if btc_client.get_tx(&challenge_assert_txid).await?.is_some() {
        tracing::info!(
            "Verifier ChallengeAssert already exists for {instance_id}:{graph_id}: verifier_index={verifier_index}, txid={challenge_assert_txid}"
        );
        return Ok(Some((challenge_assert_txid, verifier_index)));
    }
    let challenge_assert_tx_total_input_amount =
        graph.verifier_asserts[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(btc_client, challenge_assert_tx, challenge_assert_tx_total_input_amount)
        .await?;

    Ok(Some((challenge_assert_txid, verifier_index)))
}

// compute msg after ChallengeAssert is broadcast and broadcast WronglyChallenge transaction.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_challenge_assert_sent_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Challenge).await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    validate_verifier_slot(&graph, verifier_index)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;

    let Some(challenge_assert_tx) = ctx.btc_client.get_tx(&challenge_assert_txid).await? else {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network());
        let message = make_message(ctx, content);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::BitcoinTransactionPending,
            "ChallengeAssert transaction is not available from the Bitcoin backend",
        )
        .await?;
        tracing::info!(
            "Retry ChallengeAssertSent later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    };

    let challenge_witness = recover_challenge_assert_witness(&challenge_assert_tx, verifier_index)?;
    validate_challenge_witness_index(verifier_index, &challenge_witness)?;

    let labels: [Vec<u8>; goat::assert_scripts::INPUT_WIRE_NUM] = challenge_witness
        .witness
        .input_labels
        .iter()
        .map(|label| label.to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|labels: Vec<Vec<u8>>| {
            anyhow!(
                "BABE challenge witness exposes {} labels; expected {}",
                labels.len(),
                goat::assert_scripts::INPUT_WIRE_NUM
            )
        })?;
    let operator_assert_txid = challenge_assert_tx
        .input
        .first()
        .ok_or_else(|| anyhow!("published verifier assert transaction has no input"))?
        .previous_output
        .txid;
    let operator_assert_tx =
        ctx.btc_client.get_tx(&operator_assert_txid).await?.ok_or_else(|| {
            anyhow!("published operator assert transaction {operator_assert_txid} is unavailable")
        })?;
    let operator_assert_txin = operator_assert_tx
        .input
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("published operator assert transaction has no input"))?;
    let operator_assert_witness = extract_operator_assert_witness(&graph, &operator_assert_txin)
        .map_err(|e| anyhow!("failed to extract operator assert witness: {e}"))?;
    let expected_challenge_assert =
        build_verifier_assert_tx(&graph, operator_assert_txin.clone(), verifier_index, labels)?;
    if expected_challenge_assert.input.first().map(|input| &input.witness)
        != challenge_assert_tx.input.first().map(|input| &input.witness)
    {
        bail!("published verifier assert witness does not match BABE challenge labels");
    }

    let setup_state = load_babe_setup_state(ctx.local_db, instance_id, graph_id)?
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let operator_state = setup_state
        .operator
        .ok_or_else(|| anyhow!("missing operator BABE setup state for graph {graph_id}"))?;
    let candidate = selected_candidate_for_graph_index(&operator_state, verifier_index)?;
    let soldering_proof_ready = candidate.soldering_proof_ready.as_ref().ok_or_else(|| {
        anyhow!("missing soldering proof reference for verifier slot {verifier_index}")
    })?;
    let store_base_path = get_soldering_proof_payload_store_path()?;
    let payload_path = soldering_proof_payload_store_path(
        &store_base_path,
        instance_id,
        graph_id,
        soldering_proof_ready.candidate_index,
        &soldering_proof_ready.payload_hash,
    )?;
    let payload = read_soldering_proof_store_payload(&payload_path)
        .await
        .with_context(|| format!("read soldering proof payload from {payload_path}"))?;
    let payload = decode_soldering_proof_payload(soldering_proof_ready, &payload)?;
    let (_, finalized, soldering) = expand_compact_soldering_proof_payload(payload)
        .context("expand compact soldering proof payload for challenge")?;
    let prover_state = build_babe_prover_state(&candidate.setup_package, finalized, soldering)?;
    let assert_witness = TxAssertWitness {
        wots_sig: challenge_witness.witness.wots_sig.clone(),
        pi2: operator_assert_witness.pi2,
        pi3: operator_assert_witness.pi3,
    };
    let proof = recover_operator_proof_from_assert_witness(&assert_witness)
        .context("recover asserted operator proof from on-chain assert witness")?;
    let vk = crate::vk::get_vk()
        .await
        .context("load Groth16 verifying key for BABE wrongly challenged")?;
    let (_, dyn_pubin) = assert_witness.try_recover_pi1_xd().ok_or_else(|| {
        anyhow!("cannot recover dynamic input from challenge witness WOTS signature")
    })?;
    let wrongly_challenged_witness = recover_real_wrongly_challenged_witness(
        &prover_state,
        &challenge_witness,
        &proof,
        vk,
        dyn_pubin,
    )?;
    let (wrongly_challenged_input, input_amount) = operator_sign_wrongly_challenged(
        &graph,
        verifier_index,
        &wrongly_challenged_witness.final_msg,
    )?;

    let operator_keypair = OperatorMasterKey::new(get_bitvm_key()?).master_keypair();
    build_sign_and_broadcast_tx(
        ctx.btc_client,
        operator_keypair,
        vec![wrongly_challenged_input],
        input_amount,
        vec![
            goat::scripts::p2a_output(),
            // This makes the non-witness transaction size safely exceed the
            // relay minimum even before the locally funded fee input is added.
            bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: goat::scripts::generate_opreturn_script(
                    WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                ),
            },
        ],
    )
    .await?;

    Ok(())
}

const WRONGLY_CHALLENGED_OP_RETURN_DATA: &[u8] = b"wrongly-challenged";

// broadcast NoWithdraw after the ChallengeAssert timelock expires.
#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_wrongly_challenge_timeout_verifier(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    challenge_assert_txid: Txid,
    verifier_index: usize,
    content: &GOATMessageContent,
) -> Result<()> {
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        None,
        GraphStatus::Disprove,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    validate_verifier_slot(&graph, verifier_index)?;
    validate_expected_challenge_assert_txid(&graph, verifier_index, challenge_assert_txid)?;
    let verifier_master_key = VerifierMasterKey::new(get_bitvm_key()?);
    let local_verifier_pubkey: PublicKey = verifier_master_key.master_keypair().public_key().into();
    if graph.parameters.gc_data[verifier_index].verifier_pubkey != local_verifier_pubkey {
        tracing::debug!(
            "Ignore WronglyChallengeTimeout for {instance_id}:{graph_id}: local verifier does not own slot {verifier_index}"
        );
        return Ok(());
    }

    let delay_secs = avg_block_time_secs(ctx.btc_client.network());
    let message = make_message(ctx, content);
    if ctx.btc_client.get_tx(&challenge_assert_txid).await?.is_none() {
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::BitcoinTransactionPending,
            "ChallengeAssert transaction is not available from the Bitcoin backend",
        )
        .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} not found on chain"
        );
        return Ok(());
    }

    let challenge_assert_height = match ctx
        .btc_client
        .get_tx_status(&challenge_assert_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "ChallengeAssert transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: challenge assert tx {challenge_assert_txid} is not confirmed"
            );
            return Ok(());
        }
    };

    let disprove_height = challenge_assert_height
        + disprove_timelock_with_config(
            graph.parameters.instance_parameters.network,
            &graph.parameters.timelock_config,
        ) as u64;
    let bitcoin_height = ctx.btc_client.get_height().await? as u64;
    if bitcoin_height < disprove_height {
        let retry_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (disprove_height - bitcoin_height);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            retry_secs as usize,
            MessageDeferReason::TimelockPending,
            "disprove timelock has not expired",
        )
        .await?;
        tracing::info!(
            "Retry WronglyChallengeTimeout later for {instance_id}:{graph_id}: disprove timelock has not expired"
        );
        return Ok(());
    }
    if let Some(spent_txid) = outpoint_spent_txid(ctx.btc_client, &challenge_assert_txid, 0).await?
    {
        tracing::info!(
            "Skip Disprove for {instance_id}:{graph_id} slot {verifier_index}: verifier assertion output already spent by {spent_txid}"
        );
        return Ok(());
    }

    let disprove_tx = build_disprove_tx(&graph, verifier_index, None)?;
    let disprove_tx_total_input_amount =
        graph.disproves[verifier_index].prev_outs().iter().map(|o| o.value).sum::<Amount>();
    broadcast_tx_with_cpfp(ctx.btc_client, disprove_tx, disprove_tx_total_input_amount).await?;

    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id
))]
async fn handle_disprove_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    disprove_type: DisproveTxType,
    index: usize,
    challenge_finish_txid: Txid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Disprove tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        None,
        GraphStatus::Disprove,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawDisprove on GoatChain
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Disproved {
        tracing::warn!(
            "Relayer Ignore finishWithdrawDisproved for {instance_id}:{graph_id}: already posted"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let take1_txid = graph.take1.tx().compute_txid();
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let challenge_start_tx = if let Some(spent_txid) =
        outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?
    {
        if spent_txid == take1_txid {
            tracing::warn!(
                "Ignore DisproveSent for {instance_id}:{graph_id}: graph already finalized by Take1 tx: {spent_txid}"
            );
            return Ok(());
        }
        ctx.btc_client.get_tx(&spent_txid).await?
    } else {
        None
    };
    let challenge_finish_tx = match ctx.btc_client.get_tx(&challenge_finish_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore DisproveSent for {instance_id}:{graph_id}: challenge finish tx {challenge_finish_txid} not found on chain"
            );
            return Ok(());
        }
    };
    let challenge_finish_height = match ctx
        .btc_client
        .get_tx_status(&challenge_finish_txid)
        .await?
        .block_height
    {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network());
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "challenge finish transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < challenge_finish_height {
        let delay_secs = avg_block_time_secs(ctx.btc_client.network())
            * (challenge_finish_height - goat_confirmed_height);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "challenge finish block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawDisproved later for {instance_id}:{graph_id}: challenge finish tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    let result = ctx
        .goat_client
        .gateway_finish_withdraw_disproved(
            ctx.btc_client,
            &graph_id,
            disprove_type,
            index as u64,
            challenge_start_tx.as_ref(),
            &challenge_finish_tx,
        )
        .await;
    ctx.metrics_state.record_withdraw_finalize(result.is_ok());
    result?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_disprove_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Disprove tx
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::Disprove).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::OperatorKickOff,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::OperatorKickOff {
        tracing::warn!(
            "Ignore Take1Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let connector_a_vout = output_topology::kickoff::connector_a() as u64;
    let guardian_connector_vout = output_topology::kickoff::guardian_connector() as u64;
    if outpoint_spent_txid(ctx.btc_client, &kickoff_txid, connector_a_vout).await?.is_some()
        || outpoint_spent_txid(ctx.btc_client, &kickoff_txid, guardian_connector_vout)
            .await?
            .is_some()
    {
        tracing::warn!("Ignore Take1Ready for {instance_id}:{graph_id}: connectors already spent");
        return Ok(());
    }
    let kickoff_height = match ctx.btc_client.get_tx_status(&kickoff_txid).await?.block_height {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx not confirmed yet"
            );
            return Ok(());
        }
    };
    if !is_take1_timelock_expired(ctx.btc_client, kickoff_height, &graph.parameters.timelock_config)
        .await?
    {
        tracing::warn!(
            "Ignore Take1Ready for {instance_id}:{graph_id}: kickoff tx timelock not expired yet"
        );
        return Ok(());
    }
    // 1. sign & broadcast take1 txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let take1_tx = operator_sign_take1(operator_graph_keypair, &mut graph)?;
    let anchor_vout = take1_tx.output.len() as u64 - 1;
    let take1_tx_total_input_amount = graph.take1.prev_outs().iter().map(|o| o.value).sum();
    let child_tx =
        build_cpfp_txns(ctx.btc_client, &take1_tx, anchor_vout, take1_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take1_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take1_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawHappyPath on GoatChain
    let take1_txid = graph.take1.tx().compute_txid();
    let take1_tx = match ctx.btc_client.get_tx(&take1_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take1Sent for {instance_id}:{graph_id}: take1 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::WithdrawKickoffPending,
            "withdraw is initialized but kickoff has not been posted",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
        );
        return Ok(());
    }
    if withdraw_status != WithdrawStatus::Processing {
        tracing::warn!(
            "Relayer Ignore finishWithdrawHappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
        );
        return Ok(());
    }
    let take1_height = match ctx.btc_client.get_tx_status(&take1_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "take1 transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take1_height {
        let delay_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (take1_height - goat_confirmed_height);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "take1 block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawHappyPath later for {instance_id}:{graph_id} as take1 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_happy_path(ctx.btc_client, &graph_id, &take1_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take1_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take1 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake1).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_ready_operator(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by timeout task
    let message = make_message(ctx, content);
    let (mut graph, graph_status, _graph_sub_status) = match refresh_graph_status(
        ctx,
        instance_id,
        graph_id,
        Some(&message),
        GraphStatus::Challenge,
    )
    .await?
    {
        Some(v) => v,
        None => return Ok(()),
    };
    if graph_status != GraphStatus::Challenge {
        tracing::warn!(
            "Ignore Take2Ready for {instance_id}:{graph_id}: graph status is {graph_status:?}"
        );
        return Ok(());
    }
    let operator_assert_txid = graph.operator_assert.tx().compute_txid();
    let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
    // Take2 spends Connector-0, Connector-D, Connector-F, and Guardian Connector. Recheck every input before
    // signing so a stale Take2Ready cannot race an already-spent connector.
    let take2_inputs =
        graph.take2.tx().input.iter().map(|txin| txin.previous_output).collect::<Vec<OutPoint>>();
    for previous_output in take2_inputs {
        if let Some(spent_txid) =
            outpoint_spent_txid(ctx.btc_client, &previous_output.txid, previous_output.vout as u64)
                .await?
        {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: take2 input {}:{} already spent by {}",
                previous_output.txid,
                previous_output.vout,
                spent_txid
            );
            return Ok(());
        }
    }
    let operator_assert_height = match ctx
        .btc_client
        .get_tx_status(&operator_assert_txid)
        .await?
        .block_height
    {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: assert init tx not confirmed yet"
            );
            return Ok(());
        }
    };
    let watchtower_challenge_init_height = match ctx
        .btc_client
        .get_tx_status(&watchtower_challenge_init_txid)
        .await?
        .block_height
    {
        Some(height) => height,
        None => {
            tracing::warn!(
                "Ignore Take2Ready for {instance_id}:{graph_id}: watchtower challenge init tx not confirmed yet"
            );
            return Ok(());
        }
    };
    if !is_take2_timelock_expired(
        ctx.btc_client,
        operator_assert_height,
        watchtower_challenge_init_height,
        &graph.parameters.timelock_config,
    )
    .await?
    {
        tracing::warn!(
            "Ignore Take2Ready for {instance_id}:{graph_id}: take2 timelock not expired yet"
        );
        return Ok(());
    }
    // 1. sign & broadcast take2 txn
    let operator_master_key = OperatorMasterKey::new(get_bitvm_key()?);
    let operator_graph_keypair = operator_master_key.master_keypair();
    let take2_tx = operator_sign_take2(operator_graph_keypair, &mut graph)?;
    let anchor_vout = take2_tx.output.len() as u64 - 1;
    let take2_tx_total_input_amount = graph.take2.prev_outs().iter().map(|o| o.value).sum();
    let child_tx =
        build_cpfp_txns(ctx.btc_client, &take2_tx, anchor_vout, take2_tx_total_input_amount)
            .await?;
    match child_tx {
        Some(tx) => broadcast_package(ctx.btc_client, &[take2_tx, tx], true).await?,
        None => broadcast_tx(ctx.btc_client, &take2_tx).await?,
    };
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_committee(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    content: &GOATMessageContent,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let message = make_message(ctx, content);
    let (graph, _graph_status, _graph_sub_status) =
        match refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2)
            .await?
        {
            Some(v) => v,
            None => return Ok(()),
        };
    if !is_relayer() {
        return Ok(());
    }
    // 2. (Relayer) call finalizeWithdrawUnhappyPath on GoatChain
    let take2_txid = graph.take2.tx().compute_txid();
    let take2_tx = match ctx.btc_client.get_tx(&take2_txid).await? {
        Some(tx) => tx,
        None => {
            tracing::warn!(
                "Ignore Take2Sent for {instance_id}:{graph_id}: take2 tx not found on chain"
            );
            return Ok(());
        }
    };
    let withdraw_status = ctx.goat_client.gateway_get_withdraw_data(&graph_id).await?.status;
    if withdraw_status == WithdrawStatus::Initialized {
        // Kickoff not posted yet, wait for it
        let delay_secs = avg_block_time_secs(ctx.btc_client.network()) * 6; // wait for 6 blocks
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::WithdrawKickoffPending,
            "withdraw is initialized but kickoff has not been posted",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as kickoff not posted yet"
        );
        return Ok(());
    }
    if withdraw_status != WithdrawStatus::Processing {
        tracing::warn!(
            "Relayer Ignore finishWithdrawUnhappyPath for {instance_id}:{graph_id}: invalid withdraw status: {withdraw_status}"
        );
        return Ok(());
    }
    let take2_height = match ctx.btc_client.get_tx_status(&take2_txid).await?.block_height {
        Some(height) => height as u64,
        None => {
            let delay_secs = avg_block_time_secs(ctx.btc_client.network()); // wait for 1 block
            push_local_unhandled_messages_with_reason(
                ctx.local_db,
                graph_id,
                &message,
                delay_secs as usize,
                MessageDeferReason::BitcoinConfirmationPending,
                "take2 transaction is not confirmed on Bitcoin",
            )
            .await?;
            tracing::info!(
                "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx not confirmed on btc yet"
            );
            return Ok(());
        }
    };
    let goat_confirmed_height = ctx.goat_client.btc_spv_latest_height().await?;
    if goat_confirmed_height < take2_height {
        let delay_secs =
            avg_block_time_secs(ctx.btc_client.network()) * (take2_height - goat_confirmed_height);
        push_local_unhandled_messages_with_reason(
            ctx.local_db,
            graph_id,
            &message,
            delay_secs as usize,
            MessageDeferReason::GoatSpvPending,
            "take2 block is not available through GOAT SPV",
        )
        .await?;
        tracing::info!(
            "Retry finishWithdrawUnhappyPath later for {instance_id}:{graph_id} as take2 tx block not posted to goat spv contract yet"
        );
        return Ok(());
    }
    ctx.goat_client
        .gateway_finish_withdraw_unhappy_path(ctx.btc_client, &graph_id, &take2_tx)
        .await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_take2_sent_default(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // triggered by Take2 tx
    // 1. update graph status
    let _graph =
        refresh_graph_status(ctx, instance_id, graph_id, None, GraphStatus::OperatorTake2).await?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_sync_graph_request(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    // sent by other nodes when they find a graph is missing locally
    // 1. (Relayer) send SyncGraph response if have the graph
    if !is_relayer() {
        tracing::warn!("Ignore SyncGraphRequest for {instance_id}:{graph_id}: not a relayer node");
        return Ok(());
    }
    if let Some(graph) = get_graph(ctx.local_db, instance_id, graph_id).await? {
        let message_content =
            GOATMessageContent::SyncGraph(SyncGraph { instance_id, graph_id, graph });
        let message = GOATMessage::new(Actor::All, message_content);
        send_to_peer(ctx.swarm, message).await?;
    } else {
        // TODO: if no relayer has the graph, how to recover?
        tracing::warn!("Graph not found for SyncGraphRequest {instance_id}:{graph_id}");
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all, fields(instance_id = %instance_id, graph_id = %graph_id))]
async fn handle_sync_graph(
    ctx: &mut HandlerContext<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    // sent by relayer nodes in response to SyncGraphRequest
    if !ctx
        .goat_client
        .committee_mana_is_validate_peer_id(&ctx.from_peer_id.to_bytes())
        .await
        .with_context(|| {
            format!(
                "failed to validate SyncGraph sender {} against the committee registry",
                ctx.from_peer_id
            )
        })?
    {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: sender {} is not a registered committee peer",
            ctx.from_peer_id
        );
        return Ok(());
    }

    if !message_identity_matches(
        "SyncGraph",
        instance_id,
        graph_id,
        None,
        graph.parameters.instance_parameters.instance_id,
        graph.parameters.graph_id,
        graph.parameters.graph_nonce,
    ) {
        return Ok(());
    }

    validate_graph_id_on_goat(ctx.goat_client, instance_id, graph_id).await.map_err(|e| {
        anyhow!(
            "Failed to validate graph_id on GoatChain for SyncGraph {instance_id}:{graph_id}: {e}"
        )
    })?;
    let validation = validate_graph_instance_parameters(
        ctx.btc_client,
        ctx.goat_client,
        &graph.parameters.instance_parameters,
    )
    .await;
    ctx.metrics_state.record_graph_validation(validation.is_ok());
    if let Err(e) = validation {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: invalid instance parameters: {e}"
        );
        return Ok(());
    }
    let graph = BitvmGcGraph::from_simplified(graph)?;
    let graph_data = build_graph_data(&graph)?;
    let graph_data_on_goat = ctx.goat_client.gateway_get_graph_data(&graph_id).await?;
    if graph_data != graph_data_on_goat {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: reconstructed graph data does not match GoatChain"
        );
        return Ok(());
    }

    if let Err(e) = verify_graph_operator_pre_signatures(&graph) {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: invalid operator pre-signatures: {e}"
        );
        return Ok(());
    }
    if let Err(e) = verify_graph_committee_pre_signatures(&graph) {
        tracing::warn!(
            "Ignore SyncGraph for {instance_id}:{graph_id}: invalid committee pre-signatures: {e}"
        );
        return Ok(());
    }
    let simplified_graph = graph.to_simplified()?;
    let _ = store_finalized_graph_if_needed(ctx.local_db, &simplified_graph).await?;
    refresh_and_compensate(ctx, instance_id, graph_id, &graph, GraphStatus::OperatorPresigned)
        .await?;
    Ok(())
}

/// A `NodeInfo` payload is entirely self-declared, so only accept it as the
/// sender's own record: the registry is keyed by `peer_id`, and without this
/// check any peer could overwrite any other node's row.
fn accept_node_info(ctx: &HandlerContext<'_>, node_info: &NodeInfo, message_kind: &str) -> bool {
    if !node_info_matches_sender(node_info, &ctx.from_peer_id) {
        tracing::warn!(
            "Ignore {message_kind} from {}: payload claims peer_id {}",
            ctx.from_peer_id,
            node_info.peer_id
        );
        return false;
    }
    if let Err(reason) = validate_node_info_payload(node_info) {
        tracing::warn!("Ignore {message_kind} from {}: {reason}", ctx.from_peer_id);
        return false;
    }
    true
}

async fn handle_request_node_info(
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "RequestNodeInfo") {
        save_node_info(ctx.local_db, node_info).await?;
    }
    // Answer regardless: the response only carries this node's own public info,
    // and staying silent would break discovery for a misconfigured peer.
    let message_content = GOATMessageContent::ResponseNodeInfo(crate::env::get_local_node_info());
    send_to_peer(ctx.swarm, GOATMessage::new(Actor::All, message_content)).await?;
    Ok(())
}

async fn handle_response_node_info(
    ctx: &mut HandlerContext<'_>,
    node_info: &NodeInfo,
) -> Result<()> {
    if accept_node_info(ctx, node_info, "ResponseNodeInfo") {
        save_node_info(ctx.local_db, node_info).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitvm_lib::babe_adapter::{
        BABE_M_CC, BabeProverState, build_setup_package, open_and_solder,
    };
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn missing_pegin_event_is_ignored_without_enqueuing_retry() {
        let local_db = store::create_local_db("sqlite::memory:").await;
        let instance_id = Uuid::new_v4();

        let metadata =
            resolve_pegin_request_metadata(&local_db, instance_id, "0xuntrusted", i64::MAX)
                .await
                .unwrap();

        assert!(metadata.is_none());
        let mut storage_processor = local_db.acquire().await.unwrap();
        let queued = storage_processor
            .find_message_by_business_id(&instance_id, "PeginRequest")
            .await
            .unwrap();
        assert!(queued.is_none());
    }

    fn verifier_pubkey() -> PublicKey {
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
    }

    fn gc_submission() -> (CACSetupPackage, BitvmGcCircuitData, BabeProverState) {
        let package = build_setup_package(BABE_M_CC + 1).unwrap();
        let selected = (0..BABE_M_CC).collect::<Vec<_>>();
        let (_, finalized, soldering) = open_and_solder(&package, &selected).unwrap();
        let epk = &package.commits[finalized[0].index].epk;
        let h_msgs: Vec<[u8; 20]> =
            finalized.iter().map(|f| package.commits[f.index].h_msg).collect();
        let gc_data = extract_gc_circuit_data(verifier_pubkey(), epk, &h_msgs).unwrap();
        let prover_state = BabeProverState {
            package: package.clone(),
            finalized,
            soldering,
            h_msgs: gc_data.final_msg_hashlocks.clone(),
        };
        (package, gc_data, prover_state)
    }

    fn soldering_proof_ready(hash_byte: u8) -> SolderingProofReady {
        SolderingProofReady {
            instance_id: Uuid::nil(),
            graph_id: Uuid::nil(),
            candidate_index: 0,
            payload_hash: [hash_byte; 32],
            total_len: 1,
        }
    }

    fn operator_state(package: CACSetupPackage) -> OperatorBabeSetupState {
        OperatorBabeSetupState {
            candidate_verifier_pubkeys: Some(vec![verifier_pubkey()]),
            candidates: vec![OperatorVerifierCandidate {
                verifier_peer_id: vec![1],
                verifier_pubkey: verifier_pubkey(),
                setup_package: package,
                candidate_index: Some(0),
                selected_circuit_indexes: (0..BABE_M_CC).collect(),
                gc_data: None,
                soldering_proof_ready: None,
            }],
            candidate_collection_started_at: None,
            proof_collection_started_at: None,
            selected_verifier_pubkeys: None,
            asserted_operator_proof: None,
        }
    }

    #[test]
    fn freeze_operator_candidate_selects_protocol_finalized_count() {
        let package = build_setup_package(BABE_M_CC + 1).unwrap();
        let mut state = OperatorBabeSetupState {
            candidate_verifier_pubkeys: None,
            candidates: vec![OperatorVerifierCandidate {
                verifier_peer_id: vec![1],
                verifier_pubkey: verifier_pubkey(),
                setup_package: package,
                candidate_index: None,
                selected_circuit_indexes: vec![],
                gc_data: None,
                soldering_proof_ready: None,
            }],
            candidate_collection_started_at: None,
            proof_collection_started_at: None,
            selected_verifier_pubkeys: None,
            asserted_operator_proof: None,
        };

        freeze_operator_candidates(&mut state).unwrap();

        assert_eq!(state.candidates[0].selected_circuit_indexes.len(), BABE_M_CC);
    }

    #[test]
    fn candidate_records_one_slot_and_payload_reference_idempotently() {
        let (package, gc_data, prover_state) = gc_submission();
        let mut state = operator_state(package.clone());
        let soldering_proof_ready = soldering_proof_ready(1);

        record_candidate_gc_data(
            &mut state,
            verifier_pubkey(),
            0,
            &package,
            gc_data.clone(),
            &prover_state,
            soldering_proof_ready.clone(),
        )
        .unwrap();

        assert_eq!(
            state.candidates[0].gc_data.as_ref().unwrap().final_msg_hashlocks.len(),
            BABE_M_CC
        );
        assert_eq!(
            state.candidates[0].soldering_proof_ready.as_ref(),
            Some(&soldering_proof_ready)
        );

        record_candidate_gc_data(
            &mut state,
            verifier_pubkey(),
            0,
            &package,
            gc_data.clone(),
            &prover_state,
            soldering_proof_ready.clone(),
        )
        .unwrap();

        let mut conflict = prover_state;
        conflict.h_msgs[0][0] ^= 1;
        assert!(
            record_candidate_gc_data(
                &mut state,
                verifier_pubkey(),
                0,
                &package,
                gc_data,
                &conflict,
                soldering_proof_ready,
            )
            .is_err()
        );
    }

    #[test]
    fn rebuilds_prover_state_from_persisted_payload_data() {
        let package = build_setup_package(BABE_M_CC + 1).unwrap();
        let selected = (0..BABE_M_CC).collect::<Vec<_>>();
        let (_, finalized, soldering) = open_and_solder(&package, &selected).unwrap();

        let restored =
            build_babe_prover_state(&package, finalized.clone(), soldering.clone()).unwrap();

        assert_eq!(restored.package, package);
        assert_eq!(restored.finalized, finalized);
        assert_eq!(restored.soldering, soldering);
        assert_eq!(restored.h_msgs.len(), BABE_M_CC);
    }

    // ── collect_ack_txins ─────────────────────────────────────────────────────

    fn make_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn make_confirmed_ack_tx(ack_txid: Txid, wci_txid: Txid, ack_vout: u32) -> esplora_client::Tx {
        use esplora_client::{TxStatus, Vin};
        let preimage = b"test-ack-preimage".to_vec();
        esplora_client::Tx {
            txid: ack_txid,
            version: 2,
            locktime: 0,
            vin: vec![Vin {
                txid: wci_txid,
                vout: ack_vout,
                prevout: None,
                scriptsig: bitcoin::ScriptBuf::default(),
                witness: vec![preimage],
                sequence: 1,
                is_coinbase: false,
            }],
            vout: vec![],
            size: 1,
            weight: 1,
            status: TxStatus {
                confirmed: true,
                block_height: Some(800_000),
                block_hash: None,
                block_time: Some(1_000_000),
            },
            fee: 0,
        }
    }

    #[tokio::test]
    async fn collect_ack_txins_returns_only_spent_connectors() {
        let (btc_client, mock) = client::btc_chain::BTCClient::new_mock_client();
        let wci_txid = make_txid(0x00);
        let ack_txid_0 = make_txid(0x01);
        let timeout_txid_1 = make_txid(0x03);
        let timeout_txids = vec![make_txid(0x10), timeout_txid_1, make_txid(0x12)];

        // Watchtower 0 ACKed
        let vout_0 = output_topology::watchtower_challenge_init::ack_connector(0) as u32;
        mock.set_tx(ack_txid_0, make_confirmed_ack_tx(ack_txid_0, wci_txid, vout_0));

        // Watchtower 1 timed out; the timeout spend must not count as an ACK.
        let vout_1 = output_topology::watchtower_challenge_init::ack_connector(1) as u32;
        mock.set_tx(timeout_txid_1, make_confirmed_ack_tx(timeout_txid_1, wci_txid, vout_1));

        // Watchtower 2 ACKed
        let ack_txid_2 = make_txid(0x02);
        let vout_2 = output_topology::watchtower_challenge_init::ack_connector(2) as u32;
        mock.set_tx(ack_txid_2, make_confirmed_ack_tx(ack_txid_2, wci_txid, vout_2));

        let txins = collect_ack_txins(&btc_client, &wci_txid, &timeout_txids).await.unwrap();

        assert_eq!(txins.len(), 2);
        assert_eq!(txins[0].previous_output.vout, vout_0);
        assert_eq!(txins[1].previous_output.vout, vout_2);
    }

    // ── recover_challenge_assert_witness ──────────────────────────────────────

    fn build_challenge_assert_tx(
        sig: &<Wots96 as Wots>::Signature,
        labels: &[[u8; 16]],
    ) -> bitcoin::Transaction {
        let mut witness = bitcoin::Witness::new();
        let raw_wots = Wots96::signature_to_raw_witness(sig);
        for item in raw_wots.iter() {
            witness.push(item);
        }
        for label in labels {
            witness.push(label.as_slice());
        }
        witness.push([0xde, 0xad]); // placeholder script
        witness.push([0xbe, 0xef]); // placeholder control block
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn { witness, ..Default::default() }],
            output: vec![],
        }
    }

    #[test]
    fn recover_challenge_assert_witness_extracts_wots_sig_and_labels() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-challenge-witness");
        let msg = [0x42u8; 96];
        let sig = Wots96::sign(&sk, &msg);

        let labels: Vec<[u8; 16]> =
            (0..goat::assert_scripts::INPUT_WIRE_NUM).map(|i| [(i % 256) as u8; 16]).collect();

        let tx = build_challenge_assert_tx(&sig, &labels);
        let verifier_index = 3;
        let recovered = recover_challenge_assert_witness(&tx, verifier_index).unwrap();

        assert_eq!(recovered.verifier_index, verifier_index);
        assert_eq!(recovered.witness.wots_sig.len(), WOTS_SIG_COUNT);
        assert_eq!(recovered.witness.input_labels.len(), goat::assert_scripts::INPUT_WIRE_NUM);

        let mut bw = bitcoin::Witness::new();
        for item in Wots96::signature_to_raw_witness(&sig).iter() {
            bw.push(item);
        }
        assert_eq!(recovered.witness.wots_sig, Wots96::raw_witness_to_signature(&bw).to_vec());

        // labels are correctly extracted
        for (i, label) in recovered.witness.input_labels.iter().enumerate() {
            assert_eq!(label[0], (i % 256) as u8, "label {i} mismatch");
        }
    }

    #[test]
    fn recover_challenge_assert_witness_rejects_wrong_length() {
        use bitvm_lib::operator::generate_assert_wots_key;

        let (sk, _) = generate_assert_wots_key("test-wrong-len");
        let sig = Wots96::sign(&sk, &[0u8; 96]);
        let labels: Vec<[u8; 16]> = vec![[0u8; 16]; goat::assert_scripts::INPUT_WIRE_NUM];

        // one label short
        let mut short_labels = labels.clone();
        short_labels.pop();
        let bad_tx = build_challenge_assert_tx(&sig, &short_labels);
        assert!(recover_challenge_assert_witness(&bad_tx, 0).is_err());

        // no inputs at all
        let empty_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert!(recover_challenge_assert_witness(&empty_tx, 0).is_err());
    }

    #[test]
    fn wrongly_challenge_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        WRONGLY_CHALLENGED_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "wrongly-challenge transaction is {} non-witness bytes",
            tx.base_size()
        );
    }

    #[test]
    fn pubin_disprove_outputs_exceed_minimum_non_witness_size() {
        // Bitcoin Core rejects standard transactions smaller than 65 non-witness bytes.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                goat::scripts::p2a_output(),
                bitcoin::TxOut {
                    value: Amount::ZERO,
                    script_pubkey: goat::scripts::generate_opreturn_script(
                        PUBIN_DISPROVE_OP_RETURN_DATA.to_vec(),
                    ),
                },
            ],
        };

        assert!(
            tx.base_size() >= 65,
            "pubin-disprove transaction is {} non-witness bytes",
            tx.base_size()
        );
    }
}
