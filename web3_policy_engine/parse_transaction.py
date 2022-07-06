from typing import Type
from hexbytes import HexBytes
from web3.contract import Contract

from .contract_common import InputTransaction, ParsedTransaction






class Parser:
    def __init__(self, contracts: dict[HexBytes, Type[Contract]]):
        self.contracts = contracts

    def parse(self, transaction: InputTransaction) -> ParsedTransaction:
        if transaction.to not in self.contracts:
            raise ValueError("not in list of known contracts")

        contract = self.contracts[transaction.to]
        method, args = contract.decode_function_input(transaction.data)
        return ParsedTransaction(
            transaction.to, transaction.data, contract, method, args
        )
