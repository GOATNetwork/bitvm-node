fn admission_parameters(
    network: bitcoin::Network,
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
        1,
        verifiers,
    )
    .unwrap();
    BitvmGcGraphParameters {
        instance_parameters: BitvmGcInstanceParameters {
            network,
            instance_id: uuid::Uuid::from_u128(1),
            committee_pubkeys: vec![pubkey],
            committee_agg_pubkey: checked_committee_key(&[pubkey]).unwrap(),
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
        watchtower_pubkeys: vec![xonly],
        watchtower_ack_hashlocks: vec![[1; 20]],
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
