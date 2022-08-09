from typing import Any, Type
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

    def json_rpc_to_transaction(self, json_rpc: dict[str, Any]) -> InputTransaction:
        """
        Load an InputTransaction from a raw json rpc
        """

        if "params" not in json_rpc:
            raise ParseError("Invalid JSON RPC: must contain params")
        if len(json_rpc["params"]) != 1:
            raise ParseError("Invalid JSON RPC: transaction params must take exactly 1 object")
        params = json_rpc["params"][0]

        req_args = ("to", "data")
        if not all([req_arg in params for req_arg in req_args]):
            raise ParseError(f"Invalid JSON RPC: params must contain {req_args}")

        return InputTransaction(params["to"], params["data"])

    def input_transaction_to_parsed_transaction(
        self, transaction: InputTransaction
    ) -> ParsedTransaction:
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
            raise ParseError(f"Bad args for contract method: {e}")

        return ParsedTransaction(to, data, contract, method, args)

    def parse_transaction(self, json_rpc: dict[str, Any]) -> ParsedTransaction:
        """
        Parse raw json_rpc request
        """
        input_transaction = self.json_rpc_to_transaction(json_rpc)
        parsed_transaction = self.input_transaction_to_parsed_transaction(
            input_transaction
        )
        return parsed_transaction

    def parse_message(self, message: str) -> str:
        """Parse message, decoding it into a str"""
        hex_str = self.str_to_bytes(message)

        try:
            text = hex_str.decode("ascii")
        except UnicodeDecodeError as e:
            raise ParseError(f"Failed to parse message: {e}")

        return text
