from web3 import Web3
from hexbytes import HexBytes

from .schemas import Transaction

class Parser:
    def __init__(self, methods : list[str]):
        self.method_prefix_len = 4 # bytes
        self.method_names = methods
        self.methods = [self.name_to_bytes(name) for name in methods]

    def name_to_bytes(self, name : str) -> HexBytes:
        return Web3.keccak(text=name)[:self.method_prefix_len]
    
    
    def is_valid_method(self, transaction : Transaction):
        return transaction.data[:self.method_prefix_len] in self.methods
