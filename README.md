# planetmint wallet -- plntmnt

Planetmint wallet sketch.

*Warning! Beta software! Don't use it for anything serious just yet*

This repository combines a library as well as CLI tool to create Planetmint keys
stored in '.plntmnt_keystore' file, prepare, sign and send transactions.  Upon key
creation user is provided with mnemonic phrase to record and store it in a safe
please.

Keystore can have multiple "wallets" the default wallet name is "default".  CLI
provides options to derive account and index.

Derivation path has following format: m/44'/8680'/account'/0'/address'.  Where
8680 is Planetmint coin type.

As Planetmint uses Ed25519 curve, only hardened private key derivations are
supported.  Public key derivations do not work.  Key derivations are implemented
according to SLIP-10.


It is possible to import existing extended key.  During import `plntmnt` scans

Currently implemented commands:
  commit
  fulfill
  import
  init
  prepare

Check out command `--help` for more info:

## Warnings and limitations
- Tests check only subset of all possible CLI options. It is likely to brake in
  unexpected ways and CLI is not ergonomic :)
- Currently, only standard Ed25519 single output transactions are supported
