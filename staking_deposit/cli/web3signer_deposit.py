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
    WORD_LISTS_PATH,
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
    print(f"withdrawal_addr: {withdrawal_addr}")
    chain_setting = get_chain_setting(chain)
    print(f"chain_setting: {chain_setting}")

