# TODO Disallow empty passwords
import json
import os

import click
import pickledb
from base58 import b58encode
from planetmint_driver import Planetmint
from planetmint_driver.offchain import fulfill_transaction

import plntmnt_wallet.keymanagement as km
import plntmnt_wallet.keystore as ks

# Decoratoers
_wallet = click.option(
    "-w",
    "--wallet",
    help="Wallet to use",
    type=str,
    default=lambda: os.environ.get("PLNTMNT_WALLET_NAME", "default"),
)

_address = click.option(
    "-a",
    "--address",
    help="Address to use",
    type=int,
    default=lambda: os.environ.get("PLNTMNT_ACCOUNT_IDX", 0),
)

_index = click.option(
    "-i",
    "--index",
    help="Address index",
    type=int,
    default=lambda: os.environ.get("PLNTMNT_ADDRESS_IDX", 0),
)

_password = click.option(
    "-p",
    "--password",
    help="Wallet master password.  Used to encrypt and decrypt private keys",
    type=str,
    default=lambda: os.environ.get("PLNTMNT_PASSWORD"),
)

_location = click.option(
    "-L",
    "--location",
    help=("Keystore file location"),
    default=ks.get_home_path_and_warn,
)

_transaction = click.option("-t", "--transaction", help="Transaction json string", type=str, required=True)

_indent = click.option("-I", "--indent", help="Indent result", type=bool, is_flag=True)


# CLI
@click.group()
def cli():
    return


@cli.command()
@_password
@_location
@_wallet
@click.option(
    "-s",
    "--strength",
    type=int,
    default=256,
    help=("Seed strength. One of the following " "[128, 160, 192, 224, 256] default is 256"),
)
@click.option(
    "-e",
    "--entropy",
    type=str,
    help="Entropy to use for seed generation. It must be hex encoded",
)
@click.option(
    "-l",
    "--mnemonic-language",
    type=str,
    default="english",
    help=(
        "Mnemonic language. Currengly supported languages: "
        "[cinese-simplified, chinese-traditional, english, french, "
        "italian, japanese, korean, spanish]"
    ),
)
@click.option(
    "-o",
    "--no-keystore",
    type=bool,
    is_flag=True,
    help=("Do not create keystore file. Ouput result to stdout"),
)
@click.option(
    "-q",
    "--quiet",
    type=bool,
    is_flag=True,
    help=("Only ouput the resulting mnemonic seed"),
)
def init(wallet, strength, entropy, mnemonic_language, no_keystore, location, password, quiet):
    # TODO make OS checks
    # TODO no-keystore and quiet should be mutually exclusive?
    # TODO Sensible errors on bad input
    # MAYBE mutual exclusion option for click
    try:

        mnemonic_phrase = km.make_mnemonic_phrase(
            strength, mnemonic_language, bytes.fromhex(entropy) if entropy else None
        )
        wallet_dict = ks.make_wallet_dict(
            km.seed_to_extended_key(km.mnemonic_to_seed(mnemonic_phrase)),
            password,
            name=wallet,
        )

        keystore_location = "{}/{}".format(location, ks.DEFAULT_KEYSTORE_FILENAME)
        if no_keystore:
            click.echo(ks.wallet_dumps(wallet_dict))
            return
        elif not confirm_file_rewrite(keystore_location, "Keystore"):
            return

        ks.wallet_dump(wallet_dict, keystore_location)

        if quiet:
            click.echo(mnemonic_phrase)
        else:
            click.echo("Keystore initialized in:\n{}".format(keystore_location))
            click.echo("Your mnemonic phrase is:\n{}\n" "Keep it in a safe place!".format(mnemonic_phrase))
            # TODO ks.WalletError decorator
    except ks.WalletError as error:
        click.echo(error)
    except Exception:
        click.echo("Operation aborted: unrecoverable error")


@cli.command()
@_wallet
@_address
@_index
@_password
@_indent
@click.option("-o", "--operation", type=str, help="Operation CREATE/TRANSFER", required=True)
@click.option("-A", "--asset", type=str, help="Asset", required=True)
@click.option("-M", "--metadata", type=str, help="Metadata", default="{}")
def prepare(wallet, address, index, password, asset, metadata, indent, operation):
    try:
        if not operation.upper() in ["CREATE", "TRANSFER"]:
            raise ks.WalletError("Operation should be either CREATE or TRANSFER")
        key = ks.get_private_key_drv(wallet, address, index, password)
        plntmnt = Planetmint()
        prepared_creation_tx = plntmnt.transactions.prepare(
            operation=operation.upper(),
            signers=b58encode(km.privkey_to_pubkey(key.privkey)[1:]).decode(),
            asset=json.loads(asset),
            metadata=json.loads(metadata),
        )
        click.echo(json.dumps(prepared_creation_tx, indent=4 if indent else None))
        # TODO ks.WalletError decorator
    except ks.WalletError as error:
        click.echo(error)
    except json.JSONDecodeError:
        click.echo("Operation aborted during transaction parsing")
    except Exception as err:
        click.echo("Operation aborted: unrecoverable error: {}".format(err))


@cli.command()
@_wallet
@_address
@_index
@_password
@_transaction
def fulfill(wallet, password, address, index, transaction):
    try:
        key = ks.get_private_key_drv(wallet, address, index, password)
        tx = fulfill_transaction(
            json.loads(transaction),
            private_keys=[b58encode(key.privkey).decode()],
        )
        click.echo(json.dumps(tx))
    # TODO ks.WalletError decorator
    except ks.WalletError as error:
        click.echo(error)
    except json.JSONDecodeError:
        click.echo("Operation aborted during transaction parsing")
    except Exception:
        click.echo("Operation aborted: unrecoverable error")
    except:
        click.echo("Exception catched")


@cli.command()
@_transaction
@_indent
@click.option("-u", "--url", help="Planetmint URL", type=str, required=True)
def commit(transaction, url, indent):
    try:
        plntmnt = Planetmint(url)
        tx = plntmnt.transactions.send_commit(json.loads(transaction))
        click.echo(json.dumps(tx, indent=4 if indent else None))
        cache_location = "{}/{}".format(ks.get_home_path_and_warn(), ".plntmnt_cache")
        db = pickledb.load(cache_location, False)
        db.set(tx["id"], tx)
        db.dump()
    except Exception:
        click.echo("Operation aborted: unrecoverable error")


@cli.command(name="import")
@_wallet
@_password
@_location
@click.argument("type", type=str, required=True)
@click.argument("value", type=(str, str), required=True)
@click.option("-u", "--url", type=str, help="Import existing transactions from url")
@click.option("--force", is_flag=True, help="Skip confirmations")
def import_(wallet, type, value, password, location, url, force):
    """TYPE is either key or seed\n
    VALUE is a hex encoded seed or space separated master key and chaincode"""
    try:
        if type.lower() not in ["seed", "key"]:
            click.echo('TYPE must be either either "key" or "seed"')
            return

        keystore_location = "{}/{}".format(location, ks.DEFAULT_KEYSTORE_FILENAME)

        if not force and not confirm_file_rewrite(keystore_location, "Keystore"):
            return

        if type == "key":
            master_key = km.ExtendedKey(*[bytes.fromhex(i) for i in value])
        elif type == "seed":
            # master_key = km.seed_to_extended_key(bytes.fromhex(value))
            raise ks.WalletError("Not yet implemented\n" 'Use the "key" import')

        wallet_dict = ks.make_wallet_dict(master_key, password, name=wallet)

        ks.wallet_dump(wallet_dict, keystore_location)

        cache_location = "{}/{}".format(ks.get_home_path_and_warn(), ".plntmnt_cache")
        populate_tx_cache(xkey=master_key, location=cache_location, url=url)

        click.echo("Keystore initialized in:\n{}".format(keystore_location))
    except ks.WalletError as error:
        click.echo(error)
    except Exception:
        click.echo("Operation aborted: unrecoverable error")


# Utils
GAP_LIMIT = 20


def populate_tx_cache(*, xkey, location, url):
    db = pickledb.load(location, False)
    plntmnt = Planetmint(url)
    for account in range(GAP_LIMIT):
        for index in range(GAP_LIMIT):
            dxk = ks.plntmnt_derive_account(xkey, account=account, index=index)
            outputs = plntmnt.outputs.get(b58encode(km.privkey_to_pubkey(dxk.privkey)[1:]).decode())
            if not outputs:
                break
            for output in outputs:
                txid = output["transaction_id"]
                db.set(txid, plntmnt.transactions.get(asset_id=txid)[0])
    db.dump()


def confirm_file_rewrite(
    file_,
    refered_as,
    *,
    doublecheck=True,
    doublecheck_msg="Are you sure?",
    cancel_msg="Operation aborted!",
):
    if not os.path.isfile(file_):
        return True
    if click.confirm("{} exists! Rewrite?".format(refered_as)):
        if doublecheck:
            if click.confirm(doublecheck_msg):
                return True
            click.echo(cancel_msg)
            return False
        return True
    click.echo(cancel_msg)
    return False
