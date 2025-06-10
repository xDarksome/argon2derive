use std::{fmt, str::FromStr};

use anyhow::Context as _;

use crate::Cli;

pub(super) const MIN_SALT_LEN: usize = 8;

pub(super) struct Parameters {
    pub algorithm: Algorithm,
    pub memory: u32,
    pub time: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Argon2d,
    Argon2id,
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "argon2d" => Self::Argon2d,
            "argon2id" => Self::Argon2id,
            other => return Err(anyhow::anyhow!("Invalid algorithm: {other}")),
        })
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Argon2d => f.write_str("argon2d"),
            Algorithm::Argon2id => f.write_str("argon2id"),
        }
    }
}

impl Parameters {
    fn none_defined(cli: &Cli) -> bool {
        cli.memory.is_none()
            && cli.time.is_none()
            && cli.parallelism.is_none()
            && cli.salt.is_none()
    }

    pub(super) fn from_cli(cli: &Cli) -> anyhow::Result<Option<Self>> {
        if Self::none_defined(cli) {
            return Ok(None);
        }

        Self::from_cli_opt(cli)
            .context(super::MISSING_REQUIRED_PARAMETERS)
            .map(Some)
    }

    fn from_cli_opt(cli: &Cli) -> Option<Self> {
        let salt = cli.salt.as_ref().map(String::as_bytes);

        Some(Self {
            algorithm: cli.algorithm,
            memory: cli.memory? * 1024 * 1024,
            time: cli.time?,
            parallelism: cli.parallelism?,
            salt: salt.unwrap_or_default().into(),
        })
    }
}

pub(super) fn hash(
    params: &Parameters,
    password: &[u8],
    output_len: u32,
) -> anyhow::Result<Vec<u8>> {
    argon2_kdf::Hasher::new()
        .algorithm(params.algorithm.into())
        .hash_length(output_len)
        .custom_salt(&params.salt)
        .memory_cost_kib(params.memory)
        .iterations(params.time)
        .threads(params.parallelism)
        .hash(password)
        .map(|hash| hash.as_bytes().into())
        .map_err(Into::into)
}

impl From<Algorithm> for argon2_kdf::Algorithm {
    fn from(algo: Algorithm) -> Self {
        match algo {
            Algorithm::Argon2d => Self::Argon2d,
            Algorithm::Argon2id => Self::Argon2id,
        }
    }
}
