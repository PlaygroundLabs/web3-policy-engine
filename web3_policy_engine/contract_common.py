import json
from web3.contract import Contract, ContractFunction
from web3.auto import w3
from web3 import Web3
from hexbytes import HexBytes
from typing import Any, Type

def contract_from_json(filename: str) -> Type[Contract]:
    with open(filename, "r") as file_handle:
        data = json.load(file_handle)
        return w3.eth.contract(abi=data["abi"])

def method_signature(method : ContractFunction) -> HexBytes:
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


class InputTransaction:
    """
    Defines all of the required information for transaction inputs to policy engine
    """

    def __init__(self, to: HexBytes, data: HexBytes):
        self.to = to
        self.data = data


class ParsedTransaction(InputTransaction):
    """
    Everything that should be in a parsed transaction
    """

    def __init__(
        self,
        to: HexBytes,
        data: HexBytes,
        contractType: Type[Contract],
        method: ContractFunction,
        args: dict[str, Any]
    ):
        super().__init__(to, data)
        self.contractType = contractType
        self.method = method
        self.args = args
