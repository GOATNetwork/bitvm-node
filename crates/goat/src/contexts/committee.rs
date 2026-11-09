use bitcoin::{key::Keypair, Network, PublicKey, XOnlyPublicKey};

use super::base::{generate_keys_from_secret, generate_n_of_n_public_key, BaseContext};

#[derive(Debug)]
pub struct CommitteeContext {
    pub network: Network,

    pub committee_keypair: Keypair,
    pub committee_public_key: PublicKey,

    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for CommitteeContext {
    fn network(&self) -> Network {
        self.network
    }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> {
        &self.n_of_n_public_keys
    }
    fn n_of_n_public_key(&self) -> &PublicKey {
        &self.n_of_n_public_key
    }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey {
        &self.n_of_n_taproot_public_key
    }
}

impl CommitteeContext {
    pub fn new(network: Network, committee_secret: &str, n_of_n_public_keys: &[PublicKey]) -> Self {
        let (keypair, public_key) = generate_keys_from_secret(network, committee_secret);
        let (n_of_n_public_key, n_of_n_taproot_public_key) =
            generate_n_of_n_public_key(n_of_n_public_keys);

        CommitteeContext {
            network,

            committee_keypair: keypair,
            committee_public_key: public_key,

            n_of_n_public_keys: n_of_n_public_keys.to_owned(),
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}
