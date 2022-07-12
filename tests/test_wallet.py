"""Test wallet"""
import pytest

from plntmnt_wallet.keymanagement import symkey_decrypt, symkey_encrypt
from plntmnt_wallet.keystore import get_master_xprivkey


@pytest.mark.parametrize(
    "msg, password",
    [
        (b"msg", b"password"),
        (b"xxxxx", b"yyyyy"),
        (b"", b""),
        (b"\x00", b"\x00"),
        (b"\xff" * 10, b"\xff" * 10),
    ],
)
def test_can_decrypt(msg, password):
    crypt, salt = symkey_encrypt(msg, password)
    decr = symkey_decrypt(crypt, password, salt)
    assert decr == msg


def test_get_master_privkey(
    default_wallet, default_password, keymanagement_test_vectors
):
    xprivkey = get_master_xprivkey(default_wallet, "default", default_password)
    assert keymanagement_test_vectors.privkey == xprivkey.privkey
    assert keymanagement_test_vectors.chaincode == xprivkey.chaincode
