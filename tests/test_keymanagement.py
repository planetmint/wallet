from functools import reduce

import hypothesis.strategies as st
from hypothesis import example, given, settings

from plntmnt_wallet.keymanagement import (
    derive_key,
    path_to_indexes,
    privkey_to_pubkey,
    seed_to_extended_key,
)


@given(st.tuples(st.integers(min_value=0, max_value=0xFFFFFFFF)))
def test_path_to_indexes(drv_tree_position):
    # TODO Parametrize H, h and '
    path = reduce(
        lambda l, r: (
            "{}/{}".format(l, "{}H".format(r - 0x80000000) if r >= 0x80000000 else r)
        ),
        drv_tree_position,
        "m",
    )
    assert drv_tree_position == path_to_indexes(path)


def test_test_derive_extended_key(ed25519_vectors):
    # TODO parametrize vectorsets
    # TODO test fingerprint?
    for vectorset in ed25519_vectors:

        seed = vectorset["seed"]

        for chain in vectorset["chains"]:
            path, fingerprint, chaincode, privkey, pubkey = [
                chain.get(i)
                for i in [
                    "path",
                    "fingerprint",
                    "chain-code",
                    "private",
                    "public",
                ]
            ]
            drvprivkey, drvchaincode = derive_key(
                seed_to_extended_key(bytes.fromhex(seed)), path_to_indexes(path)
            )
            assert drvprivkey.hex() == privkey
            assert drvchaincode.hex() == chaincode
            assert privkey_to_pubkey(drvprivkey).hex() == pubkey
