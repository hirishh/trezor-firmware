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

from ...common import parametrize_using_common_fixtures


TO_ADDR = "0x1d1c328764a41bda0492b66baa30c4a339ff85ef"

pytestmark = [pytest.mark.altcoin, pytest.mark.ethereum]


@parametrize_using_common_fixtures(
    "ethereum/sign_tx.json",
)
def test_signtx(client, parameters, result):
    with client:
        sig_v, sig_r, sig_s = ethereum.sign_tx(
            client,
            n=parse_path(parameters["path"]),
            nonce=parameters["nonce"],
            gas_price=parameters["gas_price"],
            gas_limit=parameters["gas_limit"],
            to=parameters["to_address"],
            chain_id=parameters["chain_id"],
            value=parameters["value"],
            tx_type=parameters["tx_type"],
            data=bytes.fromhex(parameters["data"]) if parameters["data"] else None,
        )

    assert sig_r.hex() == result["sig_r_hex"]
    assert sig_s.hex() == result["sig_s_hex"]
    assert sig_v == result["sig_v"]


def test_sanity_checks(client):
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
                message_filters.EthereumTxRequest(
                    data_length=1024,
                    signature_r=None,
                    signature_s=None,
                    signature_v=None,
                ),
                message_filters.EthereumTxRequest(
                    data_length=1024,
                    signature_r=None,
                    signature_s=None,
                    signature_v=None,
                ),
                message_filters.EthereumTxRequest(
                    data_length=3,
                    signature_r=None,
                    signature_s=None,
                    signature_v=None,
                ),
                message_filters.EthereumTxRequest(data_length=None),
            ]
        )

        ethereum.sign_tx(
            client,
            n=parse_path("44'/60'/0'/0/0"),
            nonce=0,
            gas_price=20000,
            gas_limit=20000,
            to=TO_ADDR,
            value=0,
            data=b"ABCDEFGHIJKLMNOP" * 256 + b"!!!",
        )
