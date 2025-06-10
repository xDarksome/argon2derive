use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose};
use clap::{Args, Parser, Subcommand};
use rpassword::read_password;

mod age;
mod argon2;
mod config;

const APP_NAME: &str = "argon2derive";

const MISSING_REQUIRED_PARAMETERS: &str = "--memory, --time and --parallelism must be specified";

/// Determenistically derive secrets from a passphrase using Argon2
///
/// You can pipe your passphrase into stdin or you will be asked to type it.
#[derive(Debug, Parser)]
#[clap(name = APP_NAME, version = "0.1.0")]
struct Cli {
    /// Argon2 algorithm to use
    ///
    /// `argon2id`:
    /// Good all around general purpose algorithm.
    /// Use it if your use-case potentially may include running this tool on a remote machine
    /// (one you don't physically control).
    ///
    /// `argon2d`:
    /// State of the art in the realm of GPU/ASIC resistance. It is, however, vulnarable to side-chain attacks.
    /// Use it only if you know exactly what you are doing, and if you will only be using this tool on trusted machines.
    #[arg(
        global = true,
        long,
        short,
        default_value = "argon2id",
        verbatim_doc_comment
    )]
    algorithm: argon2::Algorithm,

    /// Argon2 memory cost (in GiB)
    ///
    /// The amount of memory the derivation process will require.
    ///
    /// Set this value to the largest amount of memory your system can afford to allocate.
    /// If you need to use this tool on different systems tune the memory cost to accomodate your lowest specced machine.
    #[arg(global = true, long, short, verbatim_doc_comment)]
    memory: Option<u32>,

    /// Argon2 time cost
    ///
    /// Number of hash function iterations to perform during the derivation.
    /// The amount of time required for derivation increases linearly with the number of iterations.
    ///
    /// Set this value to the largest number of iterations you are willing to wait for.
    /// If you need to use this tool on different systems tune the time cost in respect of your most frequently used machine.
    #[arg(global = true, long, short, verbatim_doc_comment)]
    time: Option<u32>,

    /// Argon2 parallelism
    ///
    /// Number of system threads to use for the derivation.
    ///
    /// Set this value to the number of (logical) cores of your CPU.
    /// If you need to use this tool on different systems tune the parallelism in respect of your most frequently used machine.
    #[arg(global = true, long, short, verbatim_doc_comment)]
    parallelism: Option<u32>,

    /// Argon2 salt
    ///
    /// Random data to be mixed with the entropy of your passphrase, needed to prevent rainbow table attacks.
    /// Not required, but strongly recommended, especially if you have a weak passphrase (you shouldn't).
    ///
    /// The salt is not a secret, you can safely publish it on the internet.
    #[arg(global = true, long, short, verbatim_doc_comment)]
    salt: Option<String>,

    /// Path to the configuration file containing Argon2 parameters
    ///
    /// If not provided, the OS-specific config directories will be searched.
    #[arg(global = true, long, short, verbatim_doc_comment)]
    config: Option<PathBuf>,

    /// Makes passphrase to be displayed while typing
    ///
    /// By default the passphrase input is being masked, this flag reverses that behaviour.
    /// Make sure you are not being shoulder-surfed! 👀
    #[arg(global = true, long, verbatim_doc_comment)]
    expose_passphrase: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a configuration file
    Configure(ConfigureArgs),

    /// Derive a raw secret
    Secret(SecretArgs),

    /// Derive an age keypair
    Age(AgeArgs),
}

#[derive(Debug, Args)]
struct ConfigureArgs {
    /// Whether to overwrite an existing config file
    #[arg(long, short)]
    overwrite: bool,
}

#[derive(Debug, Args)]
struct SecretArgs {
    /// Name of the secret
    ///
    /// Appended to Argon2 salt in order to derive the secret.
    name: String,

    /// Length in bytes
    #[arg(short, long, default_value_t = 32)]
    length: u32,

    /// Encoding format
    #[arg(short, long, value_parser = ["hex", "base64"], default_value = "hex")]
    encoding: String,
}

#[derive(Debug, Args)]
struct AgeArgs {
    /// Name of the keypair
    ///
    /// Appended to Argon2 salt in order to derive the keypair.
    name: String,
}

impl Cli {
    fn derive_secret(&self, name: &str, output_len: u32) -> anyhow::Result<Vec<u8>> {
        let mut params = match argon2::Parameters::from_cli(self)? {
            Some(params) => params,
            None => self
                .read_config()?
                .context("missing config file")?
                .try_into()?,
        };

        if params.salt.is_empty() {
            eprintln!("\nWARNING: Your salt is empty!");
        }

        params.salt.extend_from_slice(name.as_bytes());
        if params.salt.len() < argon2::MIN_SALT_LEN {
            return Err(anyhow::anyhow!(
                "Final argon2 salt (`--salt` + `--name`) is too short, should be >= {} bytes",
                argon2::MIN_SALT_LEN
            ));
        }

        let mut passphrase = String::new();

        let stdin = io::stdin();
        if stdin.is_terminal() {
            eprint!("\nEnter passphrase: ");
            io::stderr().flush()?;

            if self.expose_passphrase {
                stdin.read_line(&mut passphrase)?;
            } else {
                passphrase = read_password()?;
            }
        } else {
            stdin.read_line(&mut passphrase)?;
        }

        if passphrase.is_empty() {
            return Err(anyhow::anyhow!("Empty passphrase!"));
        }

        eprintln!("\nDeriving...");

        argon2::hash(&params, passphrase.as_bytes(), output_len)
    }

    fn read_config(&self) -> anyhow::Result<Option<config::File>> {
        let path = self.config_path()?;
        let cfg = config::File::read(&path).context("config::File::read")?;
        if let Some(cfg) = &cfg {
            eprintln!("\nUsing config ({path:?}):");
            cfg.eprint();
        }

        Ok(cfg)
    }

    fn write_config(&self, cfg: &config::File) -> anyhow::Result<()> {
        let path = self.config_path()?;

        eprintln!("\nWriting config ({path:?}):");
        cfg.eprint();

        cfg.write(&path).context("config::File::write")?;

        Ok(())
    }

    fn config_path(&self) -> anyhow::Result<PathBuf> {
        self.config
            .clone()
            .or_else(|| config::default_dir().map(|dir| dir.join("config.toml")))
            .context(
                "Unable to figure out the default config location and --config wasn't provided",
            )
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Configure(args) => {
            if cli.read_config()?.is_some() && !args.overwrite {
                return Err(anyhow::anyhow!(
                    "Config file already exists! Use --overwite if you want to overwrite the file."
                ));
            }

            let cfg = argon2::Parameters::from_cli(&cli)?
                .context(MISSING_REQUIRED_PARAMETERS)
                .map(config::File::from)?;

            cli.write_config(&cfg)?;
        }
        Commands::Secret(args) => {
            let bytes = &cli.derive_secret(&args.name, args.length)?;
            let encoded = match args.encoding.as_str() {
                "hex" => hex::encode(bytes),
                "base64" => general_purpose::STANDARD.encode(bytes),
                _ => unreachable!(),
            };
            eprintln!("\nSecret:");
            print!("{encoded}");
        }
        Commands::Age(args) => {
            let identity = age::identity(cli.derive_secret(&args.name, 32)?.try_into().unwrap())?;
            eprintln!("\nAge Identity:");
            print!("{identity}");
        }
    }

    Ok(())
}

impl TryFrom<config::File> for argon2::Parameters {
    type Error = anyhow::Error;

    fn try_from(cfg: config::File) -> anyhow::Result<Self> {
        Ok(Self {
            algorithm: cfg.algorithm.parse()?,
            memory: cfg.memory,
            time: cfg.time,
            parallelism: cfg.parallelism,
            salt: cfg.salt.map(|s| s.into_bytes()).unwrap_or_default(),
        })
    }
}

impl From<argon2::Parameters> for config::File {
    fn from(params: argon2::Parameters) -> Self {
        Self {
            algorithm: params.algorithm.to_string(),
            memory: params.memory,
            time: params.time,
            parallelism: params.parallelism,
            salt: Some(String::from_utf8(params.salt).unwrap()).filter(|s| !s.is_empty()),
        }
    }
}
