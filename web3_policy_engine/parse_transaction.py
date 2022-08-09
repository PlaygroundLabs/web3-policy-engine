from typing import Type
from web3.contract import Contract
from eth_abi.exceptions import InsufficientDataBytes
from hexbytes import HexBytes

from .contract_common import InputTransaction, ParsedTransaction, ParseError


class Parser:
    """Parser for extracting data from a raw transaction"""

    def __init__(self, contracts: dict[bytes, Type[Contract]]) -> None:
        """
        Instantiate a parser.

        :param contracts: dictionary mapping contract deployment addresses to loaded ABI information
        :type contracts: dict[bytes, Type[Contract]]
        """
        self.contracts = contracts
    
    def str_to_bytes(self, data: str) -> HexBytes:
        try:
            hex_data = HexBytes(data)
        except Exception as e:
            raise ParseError(f"'{data}' has bad byte structure: {e}")
        return hex_data


    def parse_transaction(self, transaction: InputTransaction) -> ParsedTransaction:
        """
        Parse transaction, extracting a list of inputs (as correct types)

        :param transaction: input transaction to parse
        :type transaction: InputTransaction
        """
        to = self.str_to_bytes(transaction.to)
        data = self.str_to_bytes(transaction.data)

        if to not in self.contracts:
            raise ParseError("not in list of known contracts")

        contract = self.contracts[to]
        try:
            method, args = contract.decode_function_input(transaction.data)
        except InsufficientDataBytes as e:
            raise ParseError(f'Bad args for contract method: {e}')

        return ParsedTransaction(
            to, data, contract, method, args
        )

    def parse_message(self, message: str) -> str:
        """Parse message, decoding it into a str"""
        hex_str = self.str_to_bytes(message)

        try:
            text = hex_str.decode("ascii")
        except UnicodeDecodeError as e:
            raise ParseError(f"Failed to parse message: {e}")
        
        return text
        
