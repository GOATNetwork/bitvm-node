//! Localnet helper: print the signed RPC auth headers for one request so a shell script can
//! call a signed route (e.g. `/v1/debug/engine/clear-poison`) with curl.
//!
//! Usage: BITVM_SECRET=<hex> rpc-sign <METHOD> <request-target> [body]
//! Prints three lines: `x-auth-timestamp: ..`, `x-auth-nonce: ..`, `x-auth-signature: ..`.
use bitvm_noded::rpc_service::auth::{
    AUTH_NONCE_HEADER, AUTH_SIGNATURE_HEADER, AUTH_TIMESTAMP_HEADER, sign_request_auth,
};
use http::Method;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: rpc-sign <METHOD> <request-target> [body]");
        std::process::exit(2);
    }
    let method = Method::from_bytes(args[1].as_bytes())?;
    let body = args.get(3).map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    let keypair = bitvm_noded::env::get_bitvm_key()?;
    let (timestamp, nonce, signature) = sign_request_auth(&keypair, &method, &args[2], &body);
    println!("{AUTH_TIMESTAMP_HEADER}: {timestamp}");
    println!("{AUTH_NONCE_HEADER}: {nonce}");
    println!("{AUTH_SIGNATURE_HEADER}: {signature}");
    Ok(())
}
