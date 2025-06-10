# argon2derive

## Usage
```
Determenistically derive secrets from a passphrase using Argon2

You can pipe your passphrase into stdin or you will be asked to type it.

Usage: argon2derive [OPTIONS] <COMMAND>

Commands:
  configure  Generate a configuration file
  secret     Derive a raw secret
  age        Derive an age keypair
  help       Print this message or the help of the given subcommand(s)

Options:
  -a, --algorithm <ALGORITHM>
          Argon2 algorithm to use
          
          `argon2id`:
          Good all around general purpose algorithm.
          Use it if your use-case potentially may include running this tool on a remote machine
          (one you don't physically control).
          
          `argon2d`:
          State of the art in the realm of GPU/ASIC resistance. It is, however, vulnarable to side-chain attacks.
          Use it only if you know exactly what you are doing, and if you will only be using this tool on trusted machines.
          
          [default: argon2id]

  -m, --memory <MEMORY>
          Argon2 memory cost (in GiB)
          
          The amount of memory the derivation process will require.
          
          Set this value to the largest amount of memory your system can afford to allocate.
          If you need to use this tool on different systems tune the memory cost to accomodate your lowest specced machine.

  -t, --time <TIME>
          Argon2 time cost
          
          Number of hash function iterations to perform during the derivation.
          The amount of time required for derivation increases linearly with the number of iterations.
          
          Set this value to the largest number of iterations you are willing to wait for.
          If you need to use this tool on different systems tune the time cost in respect of your most frequently used machine.

  -p, --parallelism <PARALLELISM>
          Argon2 parallelism
          
          Number of system threads to use for the derivation.
          
          Set this value to the number of (logical) cores of your CPU.
          If you need to use this tool on different systems tune the parallelism in respect of your most frequently used machine.

  -s, --salt <SALT>
          Argon2 salt
          
          Random data to be mixed with the entropy of your passphrase, needed to prevent rainbow table attacks.
          Not required, but strongly recommended, especially if you have a weak passphrase (you shouldn't).
          
          The salt is not a secret, you can safely publish it on the internet.

  -c, --config <CONFIG>
          Path to the configuration file containing Argon2 parameters
          
          If not provided, the OS-specific config directories will be searched.

      --expose-passphrase
          Makes passphrase to be displayed while typing
          
          By default the passphrase input is being masked, this flag reverses that behaviour.
          Make sure you are not being shoulder-surfed! 👀

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
