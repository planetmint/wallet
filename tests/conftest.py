"""Planetmint wallet conftest"""
import json
import os
import random
import string
from collections import namedtuple
from types import SimpleNamespace

import pickledb
import pytest
from base58 import b58encode
from planetmint_driver import Planetmint
from planetmint_driver.crypto import generate_keypair
from click.testing import CliRunner
from schema import Schema, Use

from plntmnt_wallet.keystore import PLNTMNT_PATH_TEMPLATE


@pytest.fixture
def click_runner(scope="session"):
    return CliRunner()


@pytest.fixture
def keymanagement_test_vectors():
    # TODO generate serveral more test vectors
    return SimpleNamespace(
        entropy=b"test" * 8,
        # Mnemonic.to_mnemonic(entropy)
        phrase=(
            "inner clog tackle trip fire riot spice purpose inner permit "
            "fresh trophy edge rifle spike million inflict photo bone "
            "tragic elder crawl soccer neck"
        ),
        # Mnemonic.to_seed(phrase).hex()
        seed=bytes.fromhex(
            "4e2b8ad95e94da440405b49a5c09c8f2"
            "cf00ce693b2b06f5cf681a5036de62bd"
            "0a86bc9cc5237e501d361b224d6f426d"
            "e897e39bac20085c792c6d53598908bb"
        ),
        privkey=bytes.fromhex("85e26d810b973fff21275125704dc485" "5d8245c428c9b28348bd3530690f3f57"),
        chaincode=bytes.fromhex("31be3971e42d316d9b19c3e0ad9186db" "4ac62feb601b80703e1c8643d9bb4fed"),
        pubkey=bytes.fromhex("00" "a341bde5863d9cf770599709fd582a89" "f65527b417abb890c9c964d0df4742ce"),
    )


@pytest.fixture
def default_password():
    return "default password"


@pytest.fixture
def privkey_crypt_salt(keymanagement_test_vectors, default_password):
    # TODO move to test vectors
    from plntmnt_wallet.keystore import symkey_encrypt

    crypt, salt = symkey_encrypt(keymanagement_test_vectors.privkey, default_password.encode())
    return crypt, salt


@pytest.fixture
def default_wallet(keymanagement_test_vectors, privkey_crypt_salt):
    return {
        "default": {
            "chain_code": keymanagement_test_vectors.chaincode.hex(),
            "master_pubkey": keymanagement_test_vectors.pubkey.hex(),
            "master_privkey": {
                "format": "cryptsalsa208sha256base58",
                "key": privkey_crypt_salt[0].hex(),
                "salt": privkey_crypt_salt[1].hex(),
            },
        }
    }


# ??? Can we use yeld from in pytest?
@pytest.fixture
def tmp_home_session(tmp_path, scope="session"):
    home_env_before = os.environ.get("HOME", "")
    os.environ["HOME"] = str(tmp_path)
    yield tmp_path
    os.environ["HOME"] = home_env_before


@pytest.fixture
def tmp_home(tmp_path, scope="function"):
    home_env_before = os.environ.get("HOME", "")
    os.environ["HOME"] = str(tmp_path)
    yield tmp_path
    os.environ["HOME"] = home_env_before


@pytest.fixture
def session_wallet(tmp_home_session, default_wallet):
    with open(tmp_home_session / ".plntmnt_wallet", "w") as f:
        json.dump(default_wallet, f)
    return tmp_home_session


@pytest.fixture
def plntmnt_tx_cache_location(tmp_home_session):
    return tmp_home_session / ".plntmnt_cache"


@pytest.fixture
def session_tx_cache_obj(plntmnt_tx_cache_location):
    db = pickledb.load(plntmnt_tx_cache_location, False)
    db.dump()
    return db


@pytest.fixture
def prepared_hello_world_tx():
    return {
        "inputs": [
            {
                "owners_before": ["9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS"],
                "fulfills": None,
                "fulfillment": {
                    "type": "ed25519-sha-256",
                    "public_key": "9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS",
                },
            }
        ],
        "outputs": [
            {
                "public_keys": ["9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS"],
                "condition": {
                    "details": {
                        "type": "ed25519-sha-256",
                        "public_key": "9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS",
                    },
                    "uri": "ni:///sha-256;o6-KxbkpN3M4dNPDktD2M4aQajmKwwb5HN9z10pti4Y?fpt=ed25519-sha-256&cost=131072",
                },
                "amount": "1",
            }
        ],
        "operation": "CREATE",
        "metadata": {"meta": "someta"},
        "asset": {"data": {"hello": "world"}},
        "version": "2.0",
        "id": None,
    }


@pytest.fixture
def fulfilled_hello_world_tx(prepared_hello_world_tx):
    """Place desired values in pattern matching style to create prepared tx"""
    return {
        "inputs": [
            {
                "owners_before": ["9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS"],
                "fulfills": None,
                "fulfillment": "pGSAIIBskM6EqZtE_wqlTv3gkNStd4mdlVqo7_8dX7GAL7gzgUA0b80rSW9mlLWVPkjcIO8IZFBbvH6a-xL8DP4wFzcRNNnotf44vmB6wfBHdDDoqj6TWo7D5I8NBMyx4uJTBvAP",
            }
        ],
        "outputs": [
            {
                "public_keys": ["9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS"],
                "condition": {
                    "details": {
                        "type": "ed25519-sha-256",
                        "public_key": "9eKCgG4uJ3KYM9GwBXiEFDtUzjpAqnSGVAfZHx2Uq6gS",
                    },
                    "uri": "ni:///sha-256;o6-KxbkpN3M4dNPDktD2M4aQajmKwwb5HN9z10pti4Y?fpt=ed25519-sha-256&cost=131072",
                },
                "amount": "1",
            }
        ],
        "operation": "CREATE",
        "metadata": {"meta": "someta"},
        "asset": {"data": {"hello": "world"}},
        "version": "2.0",
        "id": "d608c8c37d3d1e153f3a1c9676312afabe609ec1af50566e57235ca28ff55818",
    }


@pytest.fixture
def random_fulfilled_tx_gen():
    def closure(use_canonical_key=None):
        plntmnt = Planetmint()
        if use_canonical_key:
            alice = SimpleNamespace(
                private_key=b58encode(use_canonical_key[0]).decode(),
                public_key=b58encode(use_canonical_key[1][1:]).decode(),
            )
        else:
            alice = generate_keypair()
        prepared_creation_tx = plntmnt.transactions.prepare(
            operation="CREATE",
            signers=alice.public_key,
            asset={
                "data": {
                    "bicycle": {
                        "serial_number": "".join(random.sample(string.hexdigits, 20)),
                        "manufacturer": "bkfab",
                    },
                },
            },
            metadata={"planet": "earth"},
        )
        fulfilled_creation_tx = plntmnt.transactions.fulfill(prepared_creation_tx, private_keys=alice.private_key)
        return fulfilled_creation_tx

    return closure


@pytest.fixture
def ed25519_vectors():
    vectors_json = """[
  {
    "seed": "000102030405060708090a0b0c0d0e0f",
    "chains": [
      {
        "path": "m",
        "fingerprint": "00000000",
        "chain-code": "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
        "private": "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
        "public": "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
      },
      {
        "path": "m/0H",
        "fingerprint": "ddebc675",
        "chain-code": "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
        "private": "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        "public": "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
      },
      {
        "path": "m/0H/1H",
        "fingerprint": "13dab143",
        "chain-code": "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
        "private": "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
        "public": "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"
      },
      {
        "path": "m/0H/1H/2H",
        "fingerprint": "ebe4cb29",
        "chain-code": "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
        "private": "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
        "public": "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"
      },
      {
        "path": "m/0H/1H/2H/2H",
        "fingerprint": "316ec1c6",
        "chain-code": "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
        "private": "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
        "public": "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"
      },
      {
        "path": "m/0H/1H/2H/2H/1000000000H",
        "fingerprint": "d6322ccd",
        "chain-code": "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
        "private": "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
        "public": "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"
      }
    ]
  },
  {
    "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    "chains": [
      {
        "path": "m",
        "fingerprint": "00000000",
        "chain-code": "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
        "private": "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
        "public": "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"
      },
      {
        "path": "m/0H",
        "fingerprint": "31981b50",
        "chain-code": "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
        "private": "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
        "public": "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"
      },
      {
        "path": "m/0H/2147483647H",
        "fingerprint": "1e9411b1",
        "chain-code": "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
        "private": "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
        "public": "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"
      },
      {
        "path": "m/0H/2147483647H/1H",
        "fingerprint": "fcadf38c",
        "chain-code": "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
        "private": "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
        "public": "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"
      },
      {
        "path": "m/0H/2147483647H/1H/2147483646H",
        "fingerprint": "aca70953",
        "chain-code": "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
        "private": "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
        "public": "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
      },
      {
        "path": "m/0H/2147483647H/1H/2147483646H/2H",
        "fingerprint": "422c654b",
        "chain-code": "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
        "private": "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        "public": "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"
      }
    ]
  }
]"""
    return json.loads(vectors_json)
