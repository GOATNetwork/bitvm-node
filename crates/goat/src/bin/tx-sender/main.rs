use bitcoin::{consensus, Transaction, Txid, Wtxid};
use clap::Parser;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub struct SignedTransaction {
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    txid: Txid,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    wtxid: Wtxid,
    #[serde(with = "consensus::serde::With::<consensus::serde::Hex>")]
    pub tx: Transaction,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    file: String,

    #[arg(short, long)]
    url: String,
}

fn read_txns(file: &str) -> Vec<SignedTransaction> {
    let content = std::fs::read_to_string(file).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();

    match parsed {
        Value::Array(arr) => {
            let res: Vec<SignedTransaction> = arr
                .into_iter()
                .map(|item| serde_json::from_value(item).unwrap())
                .collect();
            res
        }

        Value::Object(_) => {
            let res: SignedTransaction = serde_json::from_value(parsed).unwrap();
            vec![res]
        }

        _ => panic!(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let txns = read_txns(&args.file);

    for tx in txns {
        println!("Sending {}...", tx.txid);
        let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx.tx);
        let client = Client::new();
        let res = client.post(&args.url).body(tx_hex).send()?;

        let status = res.status();
        let body = res.text()?;

        println!("Status: {}", status);
        println!("Response:\n{}", body);
    }

    Ok(())
}
