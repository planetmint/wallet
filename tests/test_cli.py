"""CLI Tests"""
import json
import os
import random

import hypothesis.strategies as st
import pytest
from planetmint_driver import Planetmint
from hypothesis import example, given, settings
from schema import Schema
from werkzeug.wrappers import Response

from plntmnt_wallet import _cli as cli
from plntmnt_wallet.keymanagement import (
    ExtendedKey,
    privkey_to_pubkey,
    seed_to_extended_key,
)
from plntmnt_wallet.keystore import (
    PLNTMNT_PATH_TEMPLATE,
    plntmnt_derive_account,
    get_private_key_drv,
)


@pytest.mark.parametrize(
    "account,index",
    [
        (0, 0),
        (1, 1),
        (10, 10),
        (123, 123),
        (999, 999),
        (1, 4849),
        (4849, 1),
        (0x8000000, 0x8000000),
        (0xFFFFFFF, 0xFFFFFFF),
    ],
)
def test__get_private_key_drv(
    session_wallet, default_password, keymanagement_test_vectors, account, index
):
    # TODO test raises
    key_drv = get_private_key_drv("default", account, index, default_password)
    test_xkey = ExtendedKey(
        keymanagement_test_vectors.privkey, keymanagement_test_vectors.chaincode
    )
    assert key_drv == plntmnt_derive_account(test_xkey, account, index)


def test_cli_init_default(tmp_home, click_runner):
    """This test runs init_key_store with no arguments.  Expected behaviour
    would be to create keystore file according to default keystore config.
    """
    result = click_runner.invoke(cli.init, ["--password", "1234"])
    conf_location = tmp_home / ".plntmnt_wallet"
    assert conf_location.exists()
    with open(conf_location) as conf_file:
        conf_dict = json.load(conf_file)
        assert Schema(
            {
                "default": {  # the default account
                    "chain_code": str,
                    "master_pubkey": str,
                    "master_privkey": {
                        "format": "cryptsalsa208sha256base58",
                        "salt": str,
                        "key": str,  # encrypted base58 encoded extended private key
                    },
                }
            }
        ).validate(conf_dict)
    assert result.exit_code == 0
    assert result.output.startswith(
        "Keystore initialized in:\n{}\n"
        "Your mnemonic phrase is:\n".format(conf_location)
    )


def test_cli_prepare(
    click_runner,
    session_wallet,
    default_password,
    prepared_hello_world_tx,
):
    result = click_runner.invoke(
        cli.prepare,
        [
            "--wallet",
            "default",
            "--address",
            "3",
            "--index",
            "3",
            "--operation",
            "cReAte",
            "--password",
            default_password,
            "--asset",
            '{"data":{"hello":"world"}}',
            "--metadata",
            '{"meta":"someta"}',
        ],
    )
    assert json.loads(result.output) == prepared_hello_world_tx


def test_cli_fulfill(
    click_runner,
    session_wallet,
    default_password,
    prepared_hello_world_tx,
    fulfilled_hello_world_tx,
):
    result = click_runner.invoke(
        cli.fulfill,
        [
            "--wallet",
            "default",
            "--address",
            "3",
            "--index",
            "3",
            "--password",
            default_password,
            "--transaction",
            json.dumps(prepared_hello_world_tx),
        ],
    )
    assert json.loads(result.output) == fulfilled_hello_world_tx


def test_cli_commit(
    random_fulfilled_tx_gen, click_runner, httpserver, session_tx_cache_obj
):
    ftx = random_fulfilled_tx_gen()

    def handler(request):
        reques_str = request.data.decode()
        assert json.loads(reques_str) == ftx
        return Response(reques_str)

    httpserver.expect_request(
        "/api/v1/transactions/",
        method="POST",
    ).respond_with_handler(handler)

    result = click_runner.invoke(
        cli.commit, ["--transaction", json.dumps(ftx), "--url", "http://localhost:5000"]
    )
    assert json.loads(result.output) == ftx
    tx_condition_details = [i["condition"]["details"] for i in ftx["outputs"]]
    assert len(tx_condition_details) == 1
    assert all(i["type"] == "ed25519-sha-256" for i in tx_condition_details)
    session_tx_cache_obj._loaddb()  # Reload file
    assert session_tx_cache_obj.get(ftx["id"]) == ftx


def test_cli_import(
    random_fulfilled_tx_gen,
    click_runner,
    session_tx_cache_obj,
    default_password,
    tmp_home,
):
    plntmnt = Planetmint("test.ipdb.io")
    xkey = seed_to_extended_key(os.urandom(64))

    transactions = {}
    for account in range(3):
        for index in range(3):
            dxk = plntmnt_derive_account(xkey, account=account, index=index)
            ftx = random_fulfilled_tx_gen(
                use_canonical_key=(dxk.privkey, privkey_to_pubkey(dxk.privkey))
            )
            result = plntmnt.transactions.send_commit(ftx)
            transactions[result["id"]] = result

    result = click_runner.invoke(
        cli.import_,
        [
            "key",
            xkey.privkey.hex(),
            xkey.chaincode.hex(),
            "--password",
            default_password,
            "--url",
            "test.ipdb.io",
            "--force",
        ],
    )

    session_tx_cache_obj._loaddb()  # Reload file
    for id_, tx in transactions.items():
        assert session_tx_cache_obj.get(id_) == tx
