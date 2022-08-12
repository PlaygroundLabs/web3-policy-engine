from .contract_common import ArgumentGroup
from .verify_permissions import (
    AllowedEthMethod,
    AllowedOption,
    Verifier,
    AllowedValue,
    AllowedGroup,
    AllowedContract,
    AllowedContractMethod,
    AllowedEthContractMethod,
    AllowedEthMessageMethod,
    ArgValue,
    Roles,
)

from typing import Type
import json
import yaml
from hexbytes import HexBytes
from web3.auto import w3
from web3.contract import Contract, ContractFunction


def contract_from_json(filename: str) -> Type[Contract]:
    """
    Load contract object containing ABI information from ABI file.

    Args:
        filename: path to ABI file (should be in JSON format)

    Returns:
        contract object
    """
    with open(filename, "r") as file_handle:
        data = json.load(file_handle)
        return w3.eth.contract(abi=data["abi"])


def method_signature(method: ContractFunction) -> HexBytes:
    """
    Get the signature of a contract method (this function is mostly
    useful for testing).

    Given a solidity smart contract method, the signature is obtained
    from the method's name and arguments. For example:
    "testmethod1(uint256)" has a signature of "0x6ba4caa9".

    Args:
        method: contract method to get the signature of. Must contain ABI information.

    Returns:
        method signature

    Raises:
        ValueError: If the method does not contain necessary ABI information.
    """
    if method.contract_abi is None:
        raise ValueError("contract_abi is None")

    method_abi = None
    for item in method.contract_abi:
        if "name" in item and item["name"] == method.fn_name:
            method_abi = item
            break

    if method_abi is None:
        raise ValueError(f"Method {method.fn_name} not found in abi")

    if "inputs" not in method_abi:
        raise ValueError(f"No inputs field in method contract_abi, {method_abi}")
    if method_abi["inputs"] is None:
        raise ValueError("inputs is None")
    if not all(["type" in item for item in method_abi["inputs"]]):
        raise ValueError("contract abi must describe types of all method inputs")
    inputs = ",".join([item["type"] for item in method_abi["inputs"]])  # type: ignore
    name = method.fn_name
    return w3.keccak(text=f"{name}({inputs})")[:4]


def contract_addresses_from_json(
    filename: str,
) -> tuple[dict[str, Type[Contract]], dict[bytes, Type[Contract]]]:
    """
    Load contract ABIs and registered deployment addresses.

    Args:
        filename: JSON file containing ABI filenames and addresses for each contract type (see below).

    Returns:
        1. dictionary mapping contract names to ABI information
        2. dictionary mapping deployment addresses to ABI information


    Input JSON files must contain two variables: contract_names, and addresses. The format is as follows:

    .. code-block:: json

        {
            "contract_names" : {
                "contract" : "path/to/ABI.json"
            },
            "addresses" : {
                "0x1234123412341234123412341234123412341234": "contract_name",
            }
        }
    """

    with open(filename) as file_handle:
        data = json.load(file_handle)
        contracts = {
            contract_name: contract_from_json(filename)
            for contract_name, filename in data["contract_names"].items()
        }
        addresses = {
            bytes(HexBytes(address)): contracts[contract_name]
            for address, contract_name in data["addresses"].items()
        }
        return contracts, addresses


def argument_groups_from_yaml(filename: str) -> dict[str, ArgumentGroup]:
    """
    Load an argument group from a yaml file.

    Args:
        filename: yaml file

    Returns:
        dictionary mapping group names to groups

    Expected format of file is:

    .. code-block:: yaml

        group_name:
            - item_1
            - item_2


    """
    with open(filename) as file_handle:
        data = yaml.safe_load(file_handle)
        return {
            group_name: ArgumentGroup(members) for group_name, members in data.items()
        }


def get_allowed_option(
    option: ArgValue | str, groups: dict[str, ArgumentGroup], roles: Roles
) -> AllowedOption:
    """
    Helper function for permissions_from_dict.
    Take a list of argument options as specified in a config file, and
    separates them into options (e.g. "1"), and groups (e.g. "managers")

    Args:
        option: either a valid value for an AllowedValue, or the name of an ArgumentGroup
        groups: dictionary of known ArgumentGroups and names
        roles: list of allowed roles for the resulting AllowedOption

    Return:
        instance of either an AllowedGroup or an AllowedValue
    """
    if option in groups:
        return AllowedGroup(groups[option], roles)
    return AllowedValue(option, roles)


def allowed_contracts_from_dict(
    transaction_data: dict[str, dict[str, dict[str, dict[ArgValue, Roles]]]],
    contracts: dict[str, Type[Contract]],
    groups: dict[str, ArgumentGroup] = {},
) -> AllowedEthContractMethod:
    """
    Load in the allowed smart contract transactions from a dictionary.
    Typically used to load from a config file (e.g. yaml, json).

    Args:
        transaction_data: permissions configuration for allowed smart contract transactions.
        contracts: known contracts (ABI information) and names
        groups: known argument groups and names

    Returns:
        verifier for contract eth methods
    """

    for contract_name in transaction_data:
        if contract_name not in contracts:
            raise ValueError(f"Unknown contract: {contract_name}")

    allowed_contracts = [
        AllowedContract(
            contracts[contract],
            {
                method_name: AllowedContractMethod(
                    {
                        arg_name: [
                            get_allowed_option(option, groups, roles)
                            for option, roles in options.items()
                        ]
                        for arg_name, options in args.items()
                    }
                )
                for method_name, args in methods.items()
            },
        )
        for contract, methods in transaction_data.items()
        if contract in contracts
    ]
    allowed_eth_contract_method = AllowedEthContractMethod(allowed_contracts)
    return allowed_eth_contract_method


def allowed_messages_from_dict(
    message_data: dict[str, Roles], groups: dict[str, ArgumentGroup] = {}
) -> AllowedEthMessageMethod:
    """
    Load in the allowed message-signing JSON RPC requests from a dictionary.
    Typically used to load from a config file (e.g. yaml, json).

    Args:
        message_data: permissions configuration for allowed messages to sign
        groups: known argument groups and names

    Returns:
        verifier for message eth methods
    """
    allowed_messages = [
        get_allowed_option(option, groups, roles)
        for option, roles in message_data.items()
    ]
    allowed_eth_message_method = AllowedEthMessageMethod(allowed_messages)
    return allowed_eth_message_method


def permissions_from_yaml(
    filename: str,
    contracts: dict[str, Type[Contract]],
    groups: dict[str, ArgumentGroup] = {},
) -> Verifier:
    """
    Load a Verifier object from a yaml file
    """
    with open(filename, "r") as file_handle:
        data = yaml.safe_load(file_handle)

        for item in (
            "transactions",
            "messages",
            "transaction_methods",
            "message_methods",
        ):
            if item not in data:
                raise ValueError(f"{item} is required in permissions configuration")

        transaction_data = data["transactions"]
        transaction_methods = data["transaction_methods"]
        message_data = data["messages"]
        message_methods = data["message_methods"]

        allowed_contracts = allowed_contracts_from_dict(
            transaction_data, contracts, groups
        )
        allowed_messages = allowed_messages_from_dict(message_data, groups)

        # explicitly declaring the type, because allowed_eth_methods
        # can hold both AllowedEthContractMethod and AllowedEthMessageMethod
        allowed_eth_methods: dict[str, AllowedEthMethod] = {}
        for eth_method_name in transaction_methods:
            allowed_eth_methods[eth_method_name] = allowed_contracts
        for eth_method_name in message_methods:
            allowed_eth_methods[eth_method_name] = allowed_messages

        return Verifier(allowed_eth_methods)
