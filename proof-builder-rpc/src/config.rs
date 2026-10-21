use anyhow::Context;
use proof_builder::LongRunning;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ProofBuilderConfig {
    pub header_chain: header_chain_proof::Args,
    pub commit_chain: commit_chain_proof::Args,
    pub state_chain: state_chain_proof::Args,
    pub watchtower: watchtower_proof::Args,
    pub operator: operator_proof::Args,
}

impl ProofBuilderConfig {
    pub(crate) fn new(url: &str) -> anyhow::Result<Self> {
        Self::load(url)
    }

    fn load(url: &str) -> anyhow::Result<Self> {
        let content =
            std::fs::read_to_string(url).context(format!("Failed to read config file: {url}"))?;
        Ok(toml::from_str(&content)?)
    }

    pub(crate) fn run_next<R: LongRunning + serde::Serialize>(
        args: R,
        name: String,
    ) -> anyhow::Result<R> {
        let new_args = args.rotate();
        let contents = toml::to_string_pretty(&new_args)?;
        std::fs::write(format!("{name}.ckpt"), contents)?;
        Ok(new_args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_chain_local_preference_is_optional() {
        let example = include_str!("../proof-builder.toml.example");
        let without_option = example.replace("prefer_local_headers_on_init = false", "");
        let config: ProofBuilderConfig = toml::from_str(&without_option).unwrap();
        assert!(!config.header_chain.prefer_local_headers_on_init);

        let enabled = example
            .replace("prefer_local_headers_on_init = false", "prefer_local_headers_on_init = true");
        let config: ProofBuilderConfig = toml::from_str(&enabled).unwrap();
        assert!(config.header_chain.prefer_local_headers_on_init);
    }
}
