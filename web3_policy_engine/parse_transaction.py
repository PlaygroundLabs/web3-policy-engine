from typing import Dict, Type
from web3.contract import Contract

from .contract_common import InputTransaction, ParsedTransaction


class Parser:
    """Parser for extracting data from a raw transaction"""

    def __init__(self, contracts: Dict[bytes, Type[Contract]]) -> None:
        """
        Instantiate a parser.

        :param contracts: dictionary mapping contract deployment addresses to loaded ABI information
        :type contracts: dict[bytes, Type[Contract]]
        """
        self.contracts = contracts

    def parse_transaction(self, transaction: InputTransaction) -> ParsedTransaction:
        """
        Parse transaction, extracting a list of inputs (as correct types)

        :param transaction: input transaction to parse
        :type transaction: InputTransaction
        """
        if transaction.to not in self.contracts:
            raise ValueError("not in list of known contracts")

        contract = self.contracts[transaction.to]
        method, args = contract.decode_function_input(transaction.data)
        return ParsedTransaction(
            transaction.to, transaction.data, contract, method, args
        )

    def parse_message(self, message: bytes) -> str:
        """Parse message, decoding it into a str"""
        return message.decode("ascii")
