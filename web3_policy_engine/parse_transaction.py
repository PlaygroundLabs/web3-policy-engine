from multiprocessing.sharedctypes import Value
from web3 import Web3
from hexbytes import HexBytes

from .schemas import Transaction


class Parser:
    def __init__(self, allowed: dict[HexBytes, dict[str, list[str]]]):
        self.method_prefix_len = 4  # bytes
        self.method_names = allowed
        self.method_hashes = {
            address: {
                self.name_to_hash(method): roles for method, roles in methods.items()
            }
            for address, methods in allowed.items()
        }

    def name_to_hash(self, name: str) -> HexBytes:
        return Web3.keccak(text=name)[: self.method_prefix_len]

    def is_valid_address(self, transaction: Transaction):
        return transaction.to in self.method_names

    def is_valid_method(self, transaction: Transaction):
        if not self.is_valid_address(transaction):
            # TODO: decide what to do in this case.
            # Does it make more sense to return False, or to raise error?
            # raise ValueError("Invalid address")
            return False
        return (
            transaction.data[: self.method_prefix_len]
            in self.method_hashes[transaction.to]
        )

    def is_valid_role(self, transaction: Transaction, roles: list[str]):
        if not self.is_valid_method(transaction):
            # raise ValueError("Invalid method")
            return False
        return any(
            [
                role
                in self.method_hashes[transaction.to][
                    transaction.data[: self.method_prefix_len]
                ]
                for role in roles
            ]
        )
