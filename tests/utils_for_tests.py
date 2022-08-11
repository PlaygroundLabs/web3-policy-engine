from typing import Type
from hexbytes import HexBytes
from web3.auto import w3
from web3.contract import Contract

from web3_policy_engine.contract_common import ArgValue


def make_basic_contract() -> Type[Contract]:
    """Construct a basic web3 contract with one method (taking a uint256 as input)"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                ],
                "name": "testmethod1",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
        ]
    )


def make_contract_multple_args(types: list[str]) -> Type[Contract]:
    """Construct web3 contract with one method taking various input types"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {"internalType": "uint256", "name": f"_arg{i+1}", "type": arg_type}
                    for i, arg_type in enumerate(types)
                ],
                "name": "testmethod1",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
        ]
    )


def make_contract_multiple_methods(types: list[list[str]]) -> Type[Contract]:
    """Construct web3 contract with several methods all taking various input types"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {
                        "internalType": "uint256",
                        "name": f"_arg{arg_num+1}",
                        "type": arg_type,
                    }
                    for arg_num, arg_type in enumerate(method_types)
                ],
                "name": f"testmethod{method_num+1}",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
            for method_num, method_types in enumerate(types)
        ]
    )


def format_arg(arg: ArgValue) -> HexBytes:
    val = HexBytes(arg).hex()[2:]
    return HexBytes(f"0x{val:0>64}")


def str_to_hex(item: str) -> HexBytes:
    return HexBytes(bytes(item, "ascii"))
