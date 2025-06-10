use std::{fs, io, path::PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct File {
    pub algorithm: String,
    pub memory: u32,
    pub time: u32,
    pub parallelism: u32,
    pub salt: Option<String>,
}

impl File {
    pub(super) fn read(path: &PathBuf) -> anyhow::Result<Option<Self>> {
        match fs::read_to_string(path) {
            Ok(str) => Ok(Some(toml::from_str(&str)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub(super) fn write(&self, path: &PathBuf) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }

        let str = toml::to_string_pretty(self)?;
        Ok(fs::write(path, str)?)
    }

    pub(super) fn eprint(&self) {
        let salt = self.salt.as_deref();

        eprintln!("Algorithm: {}", self.algorithm);
        eprintln!("Memory: {} (KiB)", self.memory);
        eprintln!("Time: {} (iterations)", self.time);
        eprintln!("Parallelism: {} (threads)", self.parallelism);
        eprintln!("Salt: {}", salt.unwrap_or_default());
    }
}

pub(super) fn default_dir() -> Option<PathBuf> {
    ProjectDirs::from("", "", super::APP_NAME).map(|dirs| dirs.config_dir().into())
}
