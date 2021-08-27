# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import ethereum, messages
from trezorlib.debuglink import message_filters
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ..common import MNEMONIC12

TO_ADDR = "0x1d1c328764a41bda0492b66baa30c4a339ff85ef"


def get_token_transfer_data(to_address: str, amount: str) -> bytes:
    """Generate data for transaction"""
    data = bytearray()
    # method id signalizing `transfer(address _to, uint256 _value)` function
    data.extend(bytes.fromhex("a9059cbb"))
    # 1st function argument (to - the receiver)
    data.extend(bytes.fromhex(to_address))
    # 2nd function argument (value - amount to be transferred)
    data.extend(bytes.fromhex(amount))

    return data


VECTORS = (  # params
    (
        # ADT token - test_ethereum_signtx_known_erc20_token
        # 200 000 000 in dec, decimals of ADT = 9, trezor1 displays 0.2 ADT, Trezor T 200 000 000 Wei ADT
        {
            "data": get_token_transfer_data(
                to_address="000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
                amount="000000000000000000000000000000000000000000000000000000000bebc200",
            ),
            "to_address": "000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
            "amount_to_be_transferred": "000000000000000000000000000000000000000000000000000000000bebc200",
            "path": "44'/60'/0'/0/0",
            "token_address": "0xd0d6d6c5fe4a677d343cc433536bb717bae167dd",
            "chain_id": 1,
            "nonce": 0,
            "gas_price": 20,
            "gas_limit": 20,
            "tx_type": None,
            "value": 0,  # value needs to be 0, token value is set in the contract (data)
            "sig_v": None,
            "sig_r_hex": "ec1df922115d256745410fbc2070296756583c8786e4d402a88d4e29ec513fa9",
            "sig_s_hex": "7001bfe3ba357e4a9f9e0d3a3f8a8962257615a4cf215db93e48b98999fc51b7",
        }
    ),
    (
        # unknown token address (Grzegorz Brzęczyszczykiewicz Token) - test_ethereum_signtx_unknown_erc20_token
        {
            "data": get_token_transfer_data(
                to_address="000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
                amount="0000000000000000000000000000000000000000000000000000000000000123",
            ),
            "to_address": "000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
            "amount_to_be_transferred": "0000000000000000000000000000000000000000000000000000000000000123",
            "path": "44'/60'/0'/0/1",
            "token_address": "0xfc6b5d6af8a13258f7cbd0d39e11b35e01a32f93",
            "chain_id": 1,
            "nonce": 0,
            "gas_price": 20,
            "gas_limit": 20,
            "tx_type": None,
            "value": 0,  # value needs to be 0, token value is set in the contract (data)
            "sig_v": None,
            "sig_r_hex": "2559bbf1bcb80992b6eaa96f0074b19606d8ea7bf4219e1c9ac64a12855c0cce",
            "sig_s_hex": "633a74429eb6d3aeec4ed797542236a85daab3cab15e37736b87a45697541d7a",
        }
    ),
    (
        # test_ethereum_signtx_wanchain
        {
            "data": None,
            "path": "44'/5718350'/0'/0/0",
            "token_address": "0xd0d6d6c5fe4a677d343cc433536bb717bae167dd",
            "chain_id": 1,
            "nonce": 0,
            "gas_price": 20,
            "gas_limit": 20,
            "tx_type": 1,
            "value": 100,
            "sig_v": None,
            "sig_r_hex": "d6e197029031ec90b53ed14e8233aa78b592400513ac0386d2d55cdedc3d796f",
            "sig_s_hex": "326e0d600dd1b7ee606eb531b998a6a3b3293d4995fb8cfe0677962e8a43cff6",
        }
    ),
    (
        # test_ethereum_signtx_nodata 1
        {
            "data": None,
            "path": "44'/60'/0'/0/100",
            "token_address": TO_ADDR,
            "chain_id": None,
            "nonce": 0,
            "gas_price": 20,
            "gas_limit": 20,
            "tx_type": None,
            "value": 10,
            "sig_v": 27,
            "sig_r_hex": "2f548f63ddb4cf19b6b9f922da58ff71833b967d590f3b4dcc2a70810338a982",
            "sig_s_hex": "428d35f0dca963b5196b63e7aa5e0405d8bff77d6aee1202183f1f68dacb4483",
        }
    ),
    (
        # test_ethereum_signtx_nodata 2
        {
            "data": None,
            "path": "44'/60'/0'/0/100",
            "token_address": TO_ADDR,
            "chain_id": None,
            "nonce": 123456,
            "gas_price": 20000,
            "gas_limit": 20000,
            "tx_type": None,
            "value": 12345678901234567890,
            "sig_v": 27,
            "sig_r_hex": "3bf0470cd7f5ad8d82613199f73deadc55c3c9f32f91b1a21b5ef644144ebd58",
            "sig_s_hex": "48b3ef1b2502febdf35e9ff4df0ba1fda62f042fad639eb4852a297fc9872ebd",
        }
    ),
    (
        # test_ethereum_signtx_data 1
        {
            "data": b"abcdefghijklmnop" * 16,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "chain_id": None,
            "nonce": 0,
            "gas_price": 20,
            "gas_limit": 20,
            "tx_type": None,
            "value": 10,
            "sig_v": 27,
            "sig_r_hex": "e90f9e3dbfb34861d40d67570cb369049e675c6eebfdda6b08413a2283421b85",
            "sig_s_hex": "763912b8801f76cbea7792d98123a245514beeab2f3afebb4bab637888e8393a",
        }
    ),
    (
        # test_ethereum_signtx_data 2
        {
            "data": b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "chain_id": None,
            "nonce": 123456,
            "gas_price": 20000,
            "gas_limit": 20000,
            "tx_type": None,
            "value": 12345678901234567890,
            "sig_v": 27,
            "sig_r_hex": "dd96d82d791118a55601dfcede237760d2e9734b76c373ede5362a447c42ac48",
            "sig_s_hex": "60a77558f28d483d476f9507cd8a6a4bb47b86611aaff95fd5499b9ee9ebe7ee",
        }
    ),
    # (
    #     # test_ethereum_signtx_newcontract 2
    #     # WARNING: IS FAILING - Signatures do not equal, even the "sig_v" is returned as 27
    #     {
    #         "data": b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
    #         "path": "44'/60'/0'/0/0",
    #         "token_address": "",
    #         "chain_id": None,
    #         "nonce": 123456,
    #         "gas_price": 20000,
    #         "gas_limit": 20000,
    #         "tx_type": None,
    #         "value": 12345678901234567890,
    #         "sig_v": 28,
    #         "sig_r_hex": "c86bda9de238b1c602648996561e7270a3be208da96bbf23474cb8e4014b9f93",
    #         "sig_s_hex": "18742403f75a05e7fa9868c30b36f1e55628de02d01c03084c1ff6775a13137c",
    #     }
    # ),
)

pytestmark = [pytest.mark.altcoin, pytest.mark.ethereum]


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
@pytest.mark.parametrize("params", VECTORS)
def test_ethereum_signtx(client, params):
    with client:
        sig_v, sig_r, sig_s = ethereum.sign_tx(
            client,
            n=parse_path(params["path"]),
            nonce=params["nonce"],
            gas_price=params["gas_price"],
            gas_limit=params["gas_limit"],
            to=params["token_address"],
            chain_id=params["chain_id"],
            value=params["value"],
            tx_type=params["tx_type"],
            data=params["data"],
        )

    assert sig_r.hex() == params["sig_r_hex"]
    assert sig_s.hex() == params["sig_s_hex"]
    if params["sig_v"] is not None:
        assert sig_v == params["sig_v"]


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_ethereum_sanity_checks(client):
    """Is not vectorized because these are internal-only tests that do not
    need to be exposed to the public.
    """
    # contract creation without data should fail.
    with pytest.raises(Exception):
        ethereum.sign_tx(
            client,
            n=parse_path("44'/60'/0'/0/0"),
            nonce=123456,
            gas_price=20000,
            gas_limit=20000,
            to="",
            value=12345678901234567890,
        )

    # gas overflow
    with pytest.raises(TrezorFailure):
        ethereum.sign_tx(
            client,
            n=parse_path("44'/60'/0'/0/0"),
            nonce=123456,
            gas_price=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            gas_limit=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            to=TO_ADDR,
            value=12345678901234567890,
        )

    # no gas price
    with pytest.raises(TrezorFailure):
        client.call(
            messages.EthereumSignTx(
                address_n=parse_path("44'/60'/0'/0/0"),
                nonce=b"AAA",
                gas_limit=ethereum.int_to_big_endian(10000),
                to=TO_ADDR,
                value=ethereum.int_to_big_endian(12345678901234567890),
            )
        )

    # no gas limit
    with pytest.raises(TrezorFailure):
        client.call(
            messages.EthereumSignTx(
                address_n=parse_path("44'/60'/0'/0/0"),
                nonce=b"AAA",
                gas_price=ethereum.int_to_big_endian(10000),
                to=TO_ADDR,
                value=ethereum.int_to_big_endian(12345678901234567890),
            )
        )


@pytest.mark.setup_client(mnemonic=MNEMONIC12)
def test_data_streaming(client):
    """Only verifying the expected responses, the signatures are
    checked in vectorized function above.
    """
    with client:
        client.set_expected_responses(
            [
                messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
                messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
                messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
                message_filters.EthereumTxRequest(
                    data_length=1024,
                    signature_r=None,
                    signature_s=None,
                    signature_v=None,
                ),
                message_filters.EthereumTxRequest(data_length=1024),
                message_filters.EthereumTxRequest(data_length=1024),
                message_filters.EthereumTxRequest(data_length=3),
                message_filters.EthereumTxRequest(),
            ]
        )

        sig_v, sig_r, sig_s = ethereum.sign_tx(
            client,
            n=parse_path("44'/60'/0'/0/0"),
            nonce=0,
            gas_price=20000,
            gas_limit=20000,
            to=TO_ADDR,
            value=0,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
        )
