use super::transactions::{base::BaseTransaction, pre_signed::PreSignedTransaction};
use bitcoin::Txid;
use std::fmt;
use strum::Display;

#[derive(Debug)]
pub struct NamedTx {
    pub txid: Txid,
    pub name: &'static str,
    pub confirmed: bool,
}

impl NamedTx {
    pub fn for_tx(tx: &(impl BaseTransaction + PreSignedTransaction), confirmed: bool) -> Self {
        Self {
            txid: tx.tx().compute_txid(),
            name: tx.name(),
            confirmed,
        }
    }
}

#[derive(Debug, Display)]
pub enum ConnectorError {
    ConnectorCCommitsPublicKeyEmpty,
}

#[derive(Debug)]
pub enum TransactionError {
    AlreadyMined(Txid),
    InsufficientInputAmount,
}

#[derive(Debug)]
pub enum ChunkerError {
    ValidProof,
}

#[derive(Debug)]
pub enum Error {
    Transaction(TransactionError),
    Chunker(ChunkerError),
    Connector(ConnectorError),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
