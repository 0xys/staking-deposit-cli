import click
from typing import (
    Any,
    Callable,
)

from staking_deposit.exceptions import ValidationError
from staking_deposit.key_handling.key_derivation.mnemonic import (
    reconstruct_mnemonic,
)
from staking_deposit.utils.validation import (
    verify_deposit_data_json,
    validate_int_range,
    validate_password_strength,
    validate_eth1_withdrawal_address,
    validate_bls_validator_key,
)
from staking_deposit.settings import (
    ALL_CHAINS,
    MAINNET,
    PRATER,
    get_chain_setting,
    get_devnet_chain_setting,
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
from staking_deposit.utils.validation import validate_int_range
from .generate_keys import (
    generate_keys,
    generate_keys_arguments_decorator,
)
from staking_deposit.utils.ssz import (
    compute_deposit_domain,
    compute_bls_to_execution_change_domain,
    compute_signing_root,
    BLSToExecutionChange,
    DepositData,
    DepositMessage,
    SignedBLSToExecutionChange,
)

FUNC_NAME = 'web3signer_deposit'


@click.command(
    help=load_text(['arg_web3signer_deposit', 'help'], func='web3signer_deposit'),
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
        lambda: load_text(['arg_validator_pubkey', 'prompt'], func='web3signer_deposit'),
        lambda: load_text(['arg_validator_pubkey', 'confirm'], func='web3signer_deposit'),
        lambda: load_text(['arg_validator_pubkey', 'mismatch'], func='web3signer_deposit'),
    ),
    help=lambda: load_text(['arg_validator_pubkey', 'help'], func='web3signer_deposit'),
    param_decls=['--validator-pubkey'],
    prompt=lambda: load_text(['arg_validator_pubkey', 'prompt'], func='web3signer_deposit'),
)
@jit_option(
    callback=captive_prompt_callback(
        lambda address: validate_eth1_withdrawal_address(None, None, address),
        lambda: load_text(['arg_withdrawal_addr', 'prompt'], func='web3signer_deposit'),
        lambda: load_text(['arg_withdrawal_addr', 'confirm'], func='web3signer_deposit'),
        lambda: load_text(['arg_withdrawal_addr', 'mismatch'], func='web3signer_deposit'),
    ),
    help=lambda: load_text(['arg_withdrawal_addr', 'help'], func='web3signer_deposit'),
    param_decls=['--withdrawal_addr', '--eth1_withdrawal_address'],
    prompt=lambda: load_text(['arg_withdrawal_addr', 'prompt'], func='web3signer_deposit'),
)
# @click.option('--validator_pubkey', type=str, help=load_text(['arg_validator_pubkey', 'help'], func='web3signer_deposit'))
@click.pass_context
def web3signer_deposit(ctx: click.Context, validator_pubkey: str, withdrawal_addr: str, chain: str, **kwargs: Any) -> None:
    print(f"validator_pubkey: {validator_pubkey}")
    validator_pubkey = bytes.fromhex(validator_pubkey)

    print(f"withdrawal_addr: {withdrawal_addr}")
    withdrawal_addr = bytes.fromhex(withdrawal_addr)

    print(f"chain_setting: {chain}")
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
    signature = '0xb3baa751d0a9132cfe93e4e3d5ff9075111100e3789dca219ade5a24d27e19d16b3353149da1833e9b691bb38634e8dc04469be7032132906c927d7e1a49b414730612877bc6b2810c8f202daf793d1ab0d6b5cb21d52f9e52e883859887a5d9'

    signed_deposit = DepositData(
        **deposit_msg.as_dict(),
        signature=signature,
    )

    print(f"signed_deposit: {signed_deposit}")
    return
