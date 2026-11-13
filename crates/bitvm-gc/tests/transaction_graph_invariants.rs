//! Checks actual graph templates; no Bitcoin node or proof generation is required.
use bitcoin::{Network, OutPoint, ScriptBuf, Transaction, script::Builder};
use bitvm_gc as bitvm_lib;
use bitvm_gc::{
    operator::generate_bitvm_graph,
    transactions::{base::Input, pre_signed::PreSignedTransaction},
    types::BitvmGcGraph,
};

const NETWORKS: [Network; 4] =
    [Network::Bitcoin, Network::Testnet4, Network::Signet, Network::Regtest];

fn graphs() -> impl Iterator<Item = BitvmGcGraph> {
    NETWORKS.into_iter().flat_map(|network| {
        [(1, 1), (2, 2)].into_iter().map(move |(watchtowers, verifiers)| {
            generate_bitvm_graph(graph_parameters(network, watchtowers, verifiers)).unwrap()
        })
    })
}

fn spends(tx: &Transaction, expected: &[Input]) {
    let mut actual: Vec<_> = tx.input.iter().map(|input| input.previous_output).collect();
    let mut expected: Vec<_> = expected.iter().map(|input| input.outpoint).collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected, "unexpected parents for {}", tx.compute_txid());
    assert!(actual.windows(2).all(|pair| pair[0] != pair[1]), "duplicate input");
}

#[test]
fn critical_connectors_and_competing_spends_match() {
    for graph in graphs() {
        let (deposit, confirm, refund) =
            graph.parameters.instance_parameters.build_pegin_tx().unwrap();
        let z = deposit.connector_z_input().unwrap();
        spends(confirm.tx(), std::slice::from_ref(&z));
        spends(refund.tx(), &[z]);
        let c0 = confirm.connector_0_input().unwrap();
        let a = graph.kickoff.connector_a_input().unwrap();
        let b = graph.kickoff.connector_b_input().unwrap();
        let c = graph.kickoff.connector_c_input().unwrap();
        let guardian = graph.kickoff.guardian_connector_input().unwrap();
        let d = graph.operator_assert.connector_d_input().unwrap();
        let e = graph.watchtower_challenge_init.connector_e_input().unwrap();
        let f = graph.watchtower_challenge_init.connector_f_input().unwrap();
        spends(graph.challenge.tx(), std::slice::from_ref(&a));
        spends(graph.take1.tx(), &[c0.clone(), a, b.clone(), c.clone(), guardian.clone()]);
        spends(graph.watchtower_challenge_init.tx(), &[b]);
        spends(graph.operator_assert.tx(), &[c]);
        spends(graph.take2.tx(), &[c0, d.clone(), f.clone(), guardian]);
        spends(graph.operator_commit_timeout.tx(), &[e, f.clone()]);
        // PubinDisprove spends Assert's D, not an output of Commit-Pubin.
        let pubin = bitvm_gc::verifier::build_pubin_disprove_txin(&graph, vec![]).unwrap();
        assert_eq!(pubin.previous_output, d.outpoint);
        let wci = &graph.watchtower_challenge_init;
        let n = graph.parameters.watchtower_pubkeys.len();
        assert_eq!(graph.watchtower_challenge_timeouts.len(), n);
        assert_eq!(graph.operator_challenge_nacks.len(), n);
        for i in 0..n {
            let w = wci.watchtower_connector_input(i).unwrap();
            let ack = wci.ack_connector_input(i).unwrap();
            spends(graph.watchtower_challenge_timeouts[i].tx(), &[w, ack.clone()]);
            spends(graph.operator_challenge_nacks[i].tx(), &[ack, f.clone()]);
        }
        assert_eq!(graph.verifier_asserts.len(), graph.parameters.gc_data.len());
        assert_eq!(graph.disproves.len(), graph.parameters.gc_data.len());
        for (i, assertion) in graph.verifier_asserts.iter().enumerate() {
            spends(assertion.tx(), &[graph.operator_assert.verifier_connector_input(i).unwrap()]);
            spends(
                graph.disproves[i].tx(),
                &[assertion.prover_connector_input().unwrap(), d.clone()],
            );
        }
        // The signing metadata must describe the actual producing output, not
        // merely agree with another helper's outpoint or amount calculation.
        let mut transactions: Vec<&dyn PreSignedTransaction> = vec![
            &confirm,
            &refund,
            &graph.cur_prekickoff,
            &graph.next_prekickoff,
            &graph.kickoff,
            &graph.force_skip_kickoff,
            &graph.quick_challenge,
            &graph.challenge_incomplete_kickoff,
            &graph.challenge,
            &graph.take1,
            &graph.take2,
            &graph.watchtower_challenge_init,
            &graph.operator_commit_timeout,
            &graph.operator_assert,
        ];
        transactions.extend(
            graph.watchtower_challenge_timeouts.iter().map(|tx| tx as &dyn PreSignedTransaction),
        );
        transactions.extend(
            graph.operator_challenge_nacks.iter().map(|tx| tx as &dyn PreSignedTransaction),
        );
        transactions
            .extend(graph.verifier_asserts.iter().map(|tx| tx as &dyn PreSignedTransaction));
        transactions.extend(graph.disproves.iter().map(|tx| tx as &dyn PreSignedTransaction));
        for transaction in &transactions {
            assert_eq!(transaction.prev_outs().len(), transaction.tx().input.len());
            for (input, prevout) in transaction.tx().input.iter().zip(transaction.prev_outs()) {
                let parent = if input.previous_output.txid == deposit.tx().compute_txid() {
                    Some(deposit.tx())
                } else {
                    transactions
                        .iter()
                        .find(|parent| parent.tx().compute_txid() == input.previous_output.txid)
                        .map(|parent| parent.tx())
                };
                if let Some(parent) = parent {
                    assert_eq!(prevout, &parent.output[input.previous_output.vout as usize]);
                } else {
                    // The initial PreKickoff is funded outside this graph.
                    assert_eq!(transaction.tx(), graph.cur_prekickoff.tx());
                }
            }
        }
    }
}

#[test]
fn prekickoff_dependencies_match() {
    for graph in graphs() {
        let k = graph.cur_prekickoff.kickoff_connector_input().unwrap();
        let guardian = graph.kickoff.guardian_connector_input().unwrap();
        let next_fs = graph.next_prekickoff.force_skip_connector_input().unwrap();
        let next_p = graph.next_prekickoff.prekickoff_connector_input().unwrap();
        spends(
            graph.next_prekickoff.tx(),
            &[graph.cur_prekickoff.prekickoff_connector_input().unwrap()],
        );
        spends(graph.kickoff.tx(), std::slice::from_ref(&k));
        spends(graph.force_skip_kickoff.tx(), &[k, next_fs.clone()]);
        spends(graph.quick_challenge.tx(), &[guardian.clone(), next_fs]);
        spends(graph.challenge_incomplete_kickoff.tx(), &[guardian, next_p]);
    }
}

fn csv(tx: &impl PreSignedTransaction, outpoint: OutPoint, blocks: u32) {
    let index = tx.tx().input.iter().position(|input| input.previous_output == outpoint).unwrap();
    // Exact sequence equality also rejects the disable and time-based flags.
    assert_eq!(tx.tx().input[index].sequence.to_consensus_u32(), blocks);
    let prefix: ScriptBuf = Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .into_script();
    assert!(
        tx.prev_scripts()[index].as_bytes().starts_with(prefix.as_bytes()),
        "CSV script mismatch"
    );
}

#[test]
fn csv_inputs_and_scripts_match_network_parameters() {
    for graph in graphs() {
        let t = &graph.parameters.timelock_config;
        let (deposit, _, refund) = graph.parameters.instance_parameters.build_pegin_tx().unwrap();
        csv(&refund, deposit.connector_z_input().unwrap().outpoint, t.connector_z);
        csv(&graph.take1, graph.kickoff.connector_a_input().unwrap().outpoint, t.connector_a);
        csv(
            &graph.take2,
            graph.operator_assert.connector_d_input().unwrap().outpoint,
            t.connector_d,
        );
        csv(
            &graph.take2,
            graph.watchtower_challenge_init.connector_f_input().unwrap().outpoint,
            t.connector_f,
        );
        csv(
            &graph.operator_commit_timeout,
            graph.watchtower_challenge_init.connector_e_input().unwrap().outpoint,
            t.operator_commit,
        );
        for (i, timeout) in graph.watchtower_challenge_timeouts.iter().enumerate() {
            csv(
                timeout,
                graph.watchtower_challenge_init.watchtower_connector_input(i).unwrap().outpoint,
                t.watchtower_challenge,
            );
            csv(
                &graph.operator_challenge_nacks[i],
                graph.watchtower_challenge_init.ack_connector_input(i).unwrap().outpoint,
                t.operator_ack,
            );
        }
        for (i, disprove) in graph.disproves.iter().enumerate() {
            csv(
                disprove,
                graph.verifier_asserts[i].prover_connector_input().unwrap().outpoint,
                t.prover_connector,
            );
        }
    }
}

#[test]
fn committee_signs_both_spends_of_the_force_skip_connector() {
    use bitcoin::{
        TapSighashType, XOnlyPublicKey,
        key::Keypair,
        secp256k1::{SECP256K1, SecretKey},
    };
    use bitvm_lib::{committee::*, connectors::base::TaprootConnector, operator::*};

    let mut graph = generate_bitvm_graph(graph_parameters(Network::Regtest, 1, 1)).unwrap();
    let mut seed = [0u8; 32];
    seed[28..].copy_from_slice(&1u32.to_be_bytes());
    let keypair = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&seed).unwrap());
    let committee_pubkeys = graph.parameters.instance_parameters.committee_pubkeys.clone();

    let force_skip = graph.parameters.force_skip_connector();
    assert_eq!(force_skip.n_of_n_taproot_public_key, graph.parameters.n_of_n_taproot_public_key());
    assert_eq!(
        graph.next_prekickoff.tx().output[0].script_pubkey,
        force_skip.generate_taproot_address().script_pubkey()
    );

    let witnesses = operator_pre_sign(keypair, &mut graph).unwrap();
    assert_eq!(witnesses.len(), operator_presig_num());
    verify_graph_operator_pre_signatures(&graph).unwrap();

    let (pub_nonces, sec_nonces, _) = generate_nonce_from_seed("seed".into(), 0, keypair, 1, 1);
    let agg_nonces = nonces_aggregation(std::slice::from_ref(&pub_nonces)).unwrap();
    let partial = committee_pre_sign(keypair, sec_nonces, agg_nonces.clone(), &mut graph).unwrap();
    verify_graph_committee_partial_sigs(
        &graph,
        &committee_pubkeys,
        &committee_pubkeys[0],
        &pub_nonces,
        &agg_nonces,
        &partial,
    )
    .unwrap();
    let sigs = signature_aggregation(&vec![partial], &agg_nonces, &graph).unwrap();
    push_committee_pre_signatures(&mut graph, &sigs).unwrap();
    verify_graph_committee_pre_signatures(&graph).unwrap();

    // The operator's key cannot spend the connector.
    let operator = XOnlyPublicKey::from(graph.parameters.operator_pubkey);
    for tx in [graph.quick_challenge.tx(), graph.force_skip_kickoff.tx()] {
        assert_eq!(tx.input[1].witness.len(), 3);
    }
    assert!(
        verify_taproot_pre_signed_input(&graph.quick_challenge, &operator, 1, TapSighashType::None)
            .is_err()
    );

    let restored =
        bitvm_lib::types::BitvmGcGraph::from_simplified(&graph.to_simplified().unwrap()).unwrap();
    verify_graph_operator_pre_signatures(&restored).unwrap();
    verify_graph_committee_pre_signatures(&restored).unwrap();
    assert_eq!(restored.quick_challenge.tx(), graph.quick_challenge.tx());
    assert_eq!(restored.force_skip_kickoff.tx(), graph.force_skip_kickoff.tx());
}

fn graph_parameters(
    network: bitcoin::Network,
    watchtowers: usize,
    verifiers: usize,
) -> bitvm_lib::types::BitvmGcGraphParameters {
    use bitcoin::{
        Address, Amount, OutPoint, PublicKey, Txid,
        hashes::Hash,
        secp256k1::{SECP256K1, SecretKey},
    };
    use bitvm_lib::connectors::kickoff_connectors::{
        ForceSkipConnector, KickoffConnector, PrekickoffConnector,
    };
    use bitvm_lib::transactions::{base::Input, prekickoff::PrekickoffTransaction};
    use bitvm_lib::types::*;
    let key = |index: u32| {
        let mut seed = [0u8; 32];
        seed[28..].copy_from_slice(&index.to_be_bytes());
        PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&seed).unwrap(),
        ))
    };
    let pubkey = key(1);
    let xonly = pubkey.inner.x_only_public_key().0;
    let address = Address::p2tr(SECP256K1, xonly, None, network);
    let pre = PrekickoffConnector::new(network, &xonly);
    let current = PrekickoffTransaction::new_for_validation(
        &pre,
        &ForceSkipConnector::new(network, &xonly),
        &KickoffConnector::new(network, &xonly),
        &pre,
        Input {
            outpoint: OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 0 },
            amount: Amount::from_sat(10_000_000),
        },
        vec![],
        vec![],
        1000,
        watchtowers,
        verifiers,
    )
    .unwrap();
    BitvmGcGraphParameters {
        instance_parameters: BitvmGcInstanceParameters {
            network,
            instance_id: uuid::Uuid::from_u128(1),
            committee_pubkeys: vec![pubkey],
            committee_agg_pubkey: PublicKey::new(
                musig2::KeyAggContext::new(vec![musig2::secp::Point::from(pubkey.inner)])
                    .unwrap()
                    .aggregated_pubkey::<bitcoin::secp256k1::PublicKey>(),
            ),
            pegin_amount: Amount::from_sat(1_000_000),
            user_info: UserInfo {
                depositor_evm_address: [1; 20],
                txn_fees: [1000; 3],
                inputs: vec![Input {
                    outpoint: OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 0 },
                    amount: Amount::from_sat(2_000_000),
                }],
                user_xonly_pubkey: xonly,
                user_change_address: address.clone(),
                user_refund_address: address.clone(),
            },
        },
        prekickoff_parameters: PrekickoffParameters {
            cur_prekickoff_txn: current,
            replenish_fee_inputs: vec![],
            replenish_fee_prev_outs: vec![],
            fee_amount: 1000,
        },
        timelock_config: bitvm_lib::timelocks::default_timelock_config(network),
        graph_id: uuid::Uuid::from_u128(2),
        graph_nonce: 0,
        challenge_amount: Amount::from_sat(20_000),
        operator_pubkey: pubkey,
        operator_assert_wots_pubkey: std::array::from_fn(|_| [1; 20]),
        operator_commit_pubin_wots_pubkey: std::array::from_fn(|_| [2; 20]),
        operator_receive_address: address,
        watchtower_pubkeys: (0..watchtowers)
            .map(|i| key(i as u32 + 10).inner.x_only_public_key().0)
            .collect(),
        watchtower_ack_hashlocks: vec![[1; 20]; watchtowers],
        pubin_disprove_constant: [0; 32],
        gc_data: (0..verifiers)
            .map(|i| BitvmGcCircuitData {
                verifier_pubkey: key(i as u32 + 2),
                final_msg_hashlocks: vec![[1; 20]; bitvm_lib::babe_adapter::BABE_M_CC],
                wire_hashes: std::array::from_fn(|_| bitvm_lib::assert_scripts::WireHash {
                    true_label_hash: [1; 20],
                    false_label_hash: [2; 20],
                }),
            })
            .collect(),
    }
}
