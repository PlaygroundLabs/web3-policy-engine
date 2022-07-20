import json
import yaml
from web3.contract import Contract, ContractFunction
from web3.auto import w3
from web3 import Web3
from hexbytes import HexBytes
from typing import Any, Type

def contract_from_json(filename: str) -> Type[Contract]:
    with open(filename, "r") as file_handle:
        data = json.load(file_handle)
        return w3.eth.contract(abi=data["abi"])


def method_signature(method: ContractFunction) -> HexBytes:
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
    inputs = ",".join([item["type"] for item in method_abi["inputs"]])
    name = method.fn_name
    return Web3.keccak(text=f"{name}({inputs})")[:4]


def contract_addresses_from_json(
    filename: str,
) -> tuple[dict[str, Type[Contract]], dict[bytes, Type[Contract]]]:
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



class InputTransaction:
    """
    Defines all of the required information for transaction inputs to policy engine
    """

    def __init__(self, to: bytes, data: bytes):
        self.to = to
        self.data = data


class ParsedTransaction(InputTransaction):
    """
    Everything that should be in a parsed transaction
    """

    def __init__(
        self,
        to: bytes,
        data: bytes,
        contractType: Type[Contract],
        method: ContractFunction,
        args: dict[str, Any],
    ):
        super().__init__(to, data)
        self.contractType = contractType
        self.method = method
        self.args = args


class TransactionRequest:
    """
    Complete request, with both transaction info and user role info
    """

    def __init__(self, transaction: ParsedTransaction, roles: list[str]) -> None:
        self.transaction = transaction
        self.roles = roles

class ArgumentGroup:
    """
    Argument group, typically used for lists of users in a particular category.
    TODO: consider integrating this with SQLAlchemy for easier database access
    """

    def __init__(self, members: list[Any]):
        self.members = members
    
    def contains(self, member: Any) -> bool:
        return member in self.members

def argument_groups_from_yaml(filename: str) -> dict[str, ArgumentGroup]:
    with open(filename) as file_handle:
        data = yaml.safe_load(file_handle)
        return {group_name:ArgumentGroup(members) for group_name, members in data.items()}


class InvalidPermissionsError(Exception):
    """Exception raised when the user doesn't have the required permissions"""

class UnrecognizedRequestError(Exception):
    """Exception raised when request has an unrecognized method, contract type, etc."""