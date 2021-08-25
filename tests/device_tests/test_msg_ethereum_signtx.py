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
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ..common import MNEMONIC12

TO_ADDR = "0x1d1c328764a41bda0492b66baa30c4a339ff85ef"


# TODO: agree how to handle the expected responses in all cases
# Functions are defined so that we can use client info in one special case

COMMON_EXPECTED_RESPONSES = [
    messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
    messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
    messages.EthereumTxRequest(data_length=None),
]


def common_responses(client):
    return COMMON_EXPECTED_RESPONSES


def more_responses(client):
    return [
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.EthereumTxRequest(data_length=None),
    ]


def much_more_responses(client):
    return [
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.EthereumTxRequest(
            data_length=1024,
            signature_r=None,
            signature_s=None,
            signature_v=None,
        ),
        messages.EthereumTxRequest(data_length=1024),
        messages.EthereumTxRequest(data_length=1024),
        messages.EthereumTxRequest(data_length=3),
        messages.EthereumTxRequest(),
    ]


def unknown_responses(client):
    expected_responses = [
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
        messages.ButtonRequest(code=messages.ButtonRequestType.SignTx),
    ]
    # TT asks for contract address confirmation
    if client.features.model == "T":
        expected_responses.append(
            messages.ButtonRequest(code=messages.ButtonRequestType.SignTx)
        )

    expected_responses.append(messages.EthereumTxRequest(data_length=None))

    return expected_responses


VECTORS = (  # params
    (
        # ADT token - test_ethereum_signtx_known_erc20_token
        # 200 000 000 in dec, decimals of ADT = 9, trezor1 displays 0.2 ADT, Trezor T 200 000 000 Wei ADT
        {
            "expected_responses_func": common_responses,
            "method_id": "a9059cbb",  # method id signalizing `transfer(address _to, uint256 _value)` function
            "to_address": "000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
            "amount_to_be_transferred": "000000000000000000000000000000000000000000000000000000000bebc200",
            "path": "44'/60'/0'/0/0",
            "token_address": "0xd0d6d6c5fe4a677d343cc433536bb717bae167dd",
            "chain_id": 1,
            "value": 0,  # value needs to be 0, token value is set in the contract (data)
            "sig_r_hex": "ec1df922115d256745410fbc2070296756583c8786e4d402a88d4e29ec513fa9",
            "sig_s_hex": "7001bfe3ba357e4a9f9e0d3a3f8a8962257615a4cf215db93e48b98999fc51b7",
        }
    ),
    (
        # unknown token address (Grzegorz Brzęczyszczykiewicz Token) - test_ethereum_signtx_unknown_erc20_token
        {
            "expected_responses_func": unknown_responses,
            "method_id": "a9059cbb",  # method id signalizing `transfer(address _to, uint256 _value)` function
            "to_address": "000000000000000000000000574bbb36871ba6b78e27f4b4dcfb76ea0091880b",
            "amount_to_be_transferred": "0000000000000000000000000000000000000000000000000000000000000123",
            "path": "44'/60'/0'/0/1",
            "token_address": "0xfc6b5d6af8a13258f7cbd0d39e11b35e01a32f93",
            "chain_id": 1,
            "value": 0,  # value needs to be 0, token value is set in the contract (data)
            "sig_r_hex": "2559bbf1bcb80992b6eaa96f0074b19606d8ea7bf4219e1c9ac64a12855c0cce",
            "sig_s_hex": "633a74429eb6d3aeec4ed797542236a85daab3cab15e37736b87a45697541d7a",
        }
    ),
    (
        # test_ethereum_signtx_wanchain
        {
            "expected_responses_func": common_responses,
            "path": "44'/5718350'/0'/0/0",
            "token_address": "0xd0d6d6c5fe4a677d343cc433536bb717bae167dd",
            "chain_id": 1,
            "value": 100,
            "tx_type": 1,
            "sig_r_hex": "d6e197029031ec90b53ed14e8233aa78b592400513ac0386d2d55cdedc3d796f",
            "sig_s_hex": "326e0d600dd1b7ee606eb531b998a6a3b3293d4995fb8cfe0677962e8a43cff6",
        }
    ),
    (
        # test_ethereum_signtx_nodata 1
        {
            "expected_responses_func": common_responses,
            "path": "44'/60'/0'/0/100",
            "token_address": TO_ADDR,
            "value": 10,
            "sig_v": 27,
            "sig_r_hex": "2f548f63ddb4cf19b6b9f922da58ff71833b967d590f3b4dcc2a70810338a982",
            "sig_s_hex": "428d35f0dca963b5196b63e7aa5e0405d8bff77d6aee1202183f1f68dacb4483",
        }
    ),
    (
        # test_ethereum_signtx_nodata 2
        {
            "expected_responses_func": common_responses,
            "path": "44'/60'/0'/0/100",
            "token_address": TO_ADDR,
            "nonce": 123456,
            "gas_price": 20000,
            "gas_limit": 20000,
            "value": 12345678901234567890,
            "sig_v": 27,
            "sig_r_hex": "3bf0470cd7f5ad8d82613199f73deadc55c3c9f32f91b1a21b5ef644144ebd58",
            "sig_s_hex": "48b3ef1b2502febdf35e9ff4df0ba1fda62f042fad639eb4852a297fc9872ebd",
        }
    ),
    (
        # test_ethereum_signtx_data 1
        {
            "expected_responses_func": more_responses,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "value": 10,
            "data": b"abcdefghijklmnop" * 16,
            "sig_v": 27,
            "sig_r_hex": "e90f9e3dbfb34861d40d67570cb369049e675c6eebfdda6b08413a2283421b85",
            "sig_s_hex": "763912b8801f76cbea7792d98123a245514beeab2f3afebb4bab637888e8393a",
        }
    ),
    (
        # test_ethereum_signtx_data 2
        {
            "expected_responses_func": much_more_responses,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "nonce": 123456,
            "gas_price": 20000,
            "gas_limit": 20000,
            "value": 12345678901234567890,
            "data": b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            "sig_v": 27,
            "sig_r_hex": "dd96d82d791118a55601dfcede237760d2e9734b76c373ede5362a447c42ac48",
            "sig_s_hex": "60a77558f28d483d476f9507cd8a6a4bb47b86611aaff95fd5499b9ee9ebe7ee",
        }
    ),
    (
        # test_ethereum_signtx_newcontract 1
        # contract creation without data should fail
        {
            "fail_exception": True,
            "path": "44'/60'/0'/0/0",
            "token_address": "",
            "nonce": 123456,
            "gas_price": 20000,
            "gas_limit": 20000,
            "value": 12345678901234567890,
        }
    ),
    (
        # test_ethereum_signtx_newcontract 2
        # WARNING: IS FAILING (could be because it depends on the previous fail signing)
        {
            "expected_responses_func": much_more_responses,
            "path": "44'/60'/0'/0/0",
            "token_address": "",
            "gas_price": 20000,
            "gas_limit": 20000,
            "value": 12345678901234567890,
            "data": b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
            "sig_v": 28,
            "sig_r_hex": "c86bda9de238b1c602648996561e7270a3be208da96bbf23474cb8e4014b9f93",
            "sig_s_hex": "18742403f75a05e7fa9868c30b36f1e55628de02d01c03084c1ff6775a13137c",
        }
    ),
    (
        # gas overflow - test_ethereum_sanity_checks 1
        {
            "fail_trezor": True,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "nonce": 123456,
            "gas_price": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            "gas_limit": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            "value": 12345678901234567890,
        }
    ),
    (
        # no gas price - test_ethereum_sanity_checks 2
        {
            "fail_trezor_client_call": True,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "nonce": b"AAA",
            "gas_limit": ethereum.int_to_big_endian(10000),
            "value": ethereum.int_to_big_endian(12345678901234567890),
        }
    ),
    (
        # no gas limit - test_ethereum_sanity_checks 3
        {
            "fail_trezor_client_call": True,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "nonce": b"AAA",
            "gas_price": ethereum.int_to_big_endian(10000),
            "value": ethereum.int_to_big_endian(12345678901234567890),
        }
    ),
    (
        # no nonce - test_ethereum_sanity_checks 4
        # TODO this was supposed to expect a failure if nonce is not provided.
        # Trezor does not raise such failure however.
        {
            "fail_trezor_client_call": True,
            "path": "44'/60'/0'/0/0",
            "token_address": TO_ADDR,
            "gas_price": ethereum.int_to_big_endian(10000),
            "gas_limit": ethereum.int_to_big_endian(10000),
            "value": ethereum.int_to_big_endian(12345678901234567890),
        }
    ),
)


@pytest.mark.altcoin
@pytest.mark.ethereum
class TestMsgEthereumSigntx:
    @pytest.mark.setup_client(mnemonic=MNEMONIC12)
    @pytest.mark.parametrize("params", VECTORS)
    def test_ethereum_signtx(self, client, params):
        with client:
            # TODO: this if-elif with very similar stuff is quite ugly, it should be improved
            if "fail_exception" in params and params["fail_exception"]:
                with pytest.raises(Exception):
                    ethereum.sign_tx(
                        client,
                        n=parse_path(params["path"]),
                        nonce=params["nonce"],
                        gas_price=params["gas_price"],
                        gas_limit=params["gas_limit"],
                        to=params["token_address"],
                        chain_id=params.get("chain_id"),
                        value=params["value"],
                    )
                return
            elif "fail_trezor" in params and params["fail_trezor"]:
                with pytest.raises(TrezorFailure):
                    ethereum.sign_tx(
                        client,
                        n=parse_path(params["path"]),
                        nonce=params["nonce"],
                        gas_price=params["gas_price"],
                        gas_limit=params["gas_limit"],
                        to=params["token_address"],
                        chain_id=params.get("chain_id"),
                        value=params["value"],
                    )
                return
            elif "fail_trezor_client_call" in params and params["fail_trezor_client_call"]:
                with pytest.raises(TrezorFailure):
                    args = {
                        "address_n":  parse_path(params["path"]),
                        "to": params["token_address"],
                        "value": params["value"],
                    }
                    # Adding arguments that we want to include from those which can be missing
                    for key in ["nonce", "gas_price", "gas_limit"]:
                        if key in params and params[key]:
                            args[key] = params[key]

                    client.call(
                        messages.EthereumSignTx(
                            **args
                        )
                    )
                return

            # TODO: probably differentiate between it being a function depending on
            # client (rare) or already defined list (not to pass client unecessarily)
            client.set_expected_responses(params["expected_responses_func"](client))

            # TODO: data can be already defined in the testcase itself (it is used only two times anyway)
            if "method_id" in params:
                data = bytearray()
                # method id
                data.extend(bytes.fromhex(params["method_id"]))
                # 1st function argument (to - the receiver)
                data.extend(
                    bytes.fromhex(
                        params["to_address"]
                    )
                )
                # 2nd function argument (value - amount to be transferred)
                data.extend(
                    bytes.fromhex(
                        params["amount_to_be_transferred"]
                    )
                )
            else:
                data = params.get("data")

            sig_v, sig_r, sig_s = ethereum.sign_tx(
                client,
                n=parse_path(params["path"]),
                nonce=params.get("nonce") or 0,
                gas_price=params.get("gas_price") or 20,
                gas_limit=params.get("gas_limit") or 20,
                to=params["token_address"],
                chain_id=params.get("chain_id"),
                value=params["value"],
                tx_type=params.get("tx_type"),
                data=data,
            )

            # taken from T1 might not be 100% correct but still better than nothing
            assert (
                sig_r.hex() == params["sig_r_hex"]
            )
            assert (
                sig_s.hex() == params["sig_s_hex"]
            )
            if "sig_v" in params:
                assert (
                    sig_v == params["sig_v"]
                )
