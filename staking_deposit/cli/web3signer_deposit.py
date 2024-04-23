import click
from typing import (
    Any,
)

from staking_deposit.utils.validation import (
    validate_eth1_withdrawal_address,
    validate_bls_validator_key,
    validate_web3signer_endpoint,
)
from staking_deposit.settings import (
    ALL_CHAINS,
    MAINNET,
    PRATER,
    BaseChainSetting,
    DEPOSIT_CLI_VERSION,
    get_chain_setting,
)
from staking_deposit.utils.constants import (
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    WORD_LISTS_PATH,
    ETH2GWEI,
)
from staking_deposit.utils.click import (
    captive_prompt_callback,
    choice_prompt_func,
    jit_option,
)
from staking_deposit.exceptions import ValidationError
from staking_deposit.utils.intl import (
    closest_match,
    load_text,
)
from staking_deposit.utils.intl import load_text

from staking_deposit.utils.ssz import (
    compute_deposit_domain,
    compute_signing_root,
    BLSToExecutionChange,
    DepositData,
    DepositMessage,
    SignedBLSToExecutionChange,
)

import http.client
import json

def sign(endpoint: str, signing_root: bytes, deposit_msg: DepositMessage, chain: BaseChainSetting) -> bytes:
    conn = http.client.HTTPConnection(endpoint)
    headers = {'Content-Type': 'application/json'}
    pubkey = deposit_msg['pubkey'].hex()
    wc = deposit_msg['withdrawal_credentials'].hex()
    data = {
        'type': 'DEPOSIT',
        'signingRoot': f'0x{signing_root.hex()}',
        'deposit': {
            'pubkey': f'0x{pubkey}',
            'withdrawal_credentials': f'0x{wc}',
            'amount': f'{32*ETH2GWEI}',
            'genesis_fork_version': f'0x{chain.GENESIS_FORK_VERSION.hex()}',
        }
    }
    path = f'/api/v1/eth2/sign/0x{pubkey}'
    
    conn.request("POST", path, json.dumps(data).encode('utf-8'), headers)

    res = conn.getresponse()
    if res.status != 200:
        print(path)
        print(data)
        print(f"Error: {res.status} {res.reason}")
        return None
    
    content = res.read().decode('utf-8')
    print(content)

    if content[:2] == '0x':
        content = content[2:]
    
    conn.close()
    return bytes.fromhex(content)

FUNC_NAME = 'web3signer_deposit'


@click.command(
    help=load_text(['arg_web3signer_deposit', 'help'], func=FUNC_NAME),
)
@jit_option(
    callback=captive_prompt_callback(
        lambda endpoint: validate_web3signer_endpoint(None, None, endpoint),
        lambda: load_text(['arg_endpoint', 'prompt'], func=FUNC_NAME),
    ),
    help=lambda: load_text(['arg_endpoint', 'help'], func=FUNC_NAME),
    param_decls=['--endpoint'],
    prompt=lambda: load_text(['arg_endpoint', 'prompt'], func=FUNC_NAME),
)
@jit_option(
    callback=captive_prompt_callback(
        lambda x: closest_match(x, list(ALL_CHAINS.keys())),
        choice_prompt_func(
            lambda: load_text(['arg_chain', 'prompt'], func=FUNC_NAME),
            list(ALL_CHAINS.keys())
        ),
    ),
    default=MAINNET,
    help=lambda: load_text(['arg_chain', 'help'], func=FUNC_NAME),
    param_decls='--chain',
    prompt=choice_prompt_func(
        lambda: load_text(['arg_chain', 'prompt'], func=FUNC_NAME),
        # Since `prater` is alias of `goerli`, do not show `prater` in the prompt message.
        list(key for key in ALL_CHAINS.keys() if key != PRATER)
    ),
)
@jit_option(
    callback=captive_prompt_callback(
        lambda pubkey: validate_bls_validator_key(None, None, pubkey),
        lambda: load_text(['arg_validator_pubkey', 'prompt'], func=FUNC_NAME),
    ),
    help=lambda: load_text(['arg_validator_pubkey', 'help'], func=FUNC_NAME),
    param_decls=['--validator-pubkey'],
    prompt=lambda: load_text(['arg_validator_pubkey', 'prompt'], func=FUNC_NAME),
)
@jit_option(
    callback=captive_prompt_callback(
        lambda address: validate_eth1_withdrawal_address(None, None, address),
        lambda: load_text(['arg_withdrawal_addr', 'prompt'], func=FUNC_NAME),
        # lambda: load_text(['arg_withdrawal_addr', 'confirm'], func='web3signer_deposit'),
        None,
        lambda: load_text(['arg_withdrawal_addr', 'mismatch'], func=FUNC_NAME),
    ),
    help=lambda: load_text(['arg_withdrawal_addr', 'help'], func=FUNC_NAME),
    param_decls=['--withdrawal-addr', '--eth1-withdrawal-address'],
    prompt=lambda: load_text(['arg_withdrawal_addr', 'prompt'], func=FUNC_NAME),
)
@click.pass_context
def web3signer_deposit(ctx: click.Context, endpoint: str, validator_pubkey: str, withdrawal_addr: str, chain: str, **kwargs: Any) -> None:
    print(f"validator-pubkey: {validator_pubkey}")
    validator_pubkey = bytes.fromhex(validator_pubkey)

    print(f"withdrawal-addr: {withdrawal_addr}")
    withdrawal_addr = bytes.fromhex(withdrawal_addr)

    print(f"chain-setting: {chain}")
    chain_setting = get_chain_setting(chain)

    withdrawal_credentials = ETH1_ADDRESS_WITHDRAWAL_PREFIX
    withdrawal_credentials += b'\x00' * 11
    withdrawal_credentials += withdrawal_addr
    deposit_msg = DepositMessage(
        pubkey=validator_pubkey,
        withdrawal_credentials=withdrawal_credentials,
        amount=32*ETH2GWEI,
    )
    domain = compute_deposit_domain(fork_version=chain_setting.GENESIS_FORK_VERSION)
    signing_root = compute_signing_root(deposit_msg, domain)

    # call sign(DEPOSIT, signing_root, deposit_msg)
    # signature = bytes.fromhex('b3baa751d0a9132cfe93e4e3d5ff9075111100e3789dca219ade5a24d27e19d16b3353149da1833e9b691bb38634e8dc04469be7032132906c927d7e1a49b414730612877bc6b2810c8f202daf793d1ab0d6b5cb21d52f9e52e883859887a5d9')
    signature = sign(endpoint, signing_root, deposit_msg, chain_setting)
    if signature is None:
        print("Failed to sign the deposit message.")
        return

    signed_deposit = DepositData(
        **deposit_msg.as_dict(),
        signature=signature,
    )

    datum_dict = signed_deposit.as_dict()
    datum_dict.update({'deposit_message_root': deposit_msg.hash_tree_root})
    datum_dict.update({'deposit_data_root': signed_deposit.hash_tree_root})
    datum_dict.update({'fork_version': chain_setting.GENESIS_FORK_VERSION})
    datum_dict.update({'network_name': chain_setting.NETWORK_NAME})
    datum_dict.update({'deposit_cli_version': DEPOSIT_CLI_VERSION})

    print(datum_dict)
    return
