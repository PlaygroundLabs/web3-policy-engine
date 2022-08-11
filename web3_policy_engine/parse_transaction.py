from typing import Any, Type
from web3.contract import Contract
from eth_abi.exceptions import InsufficientDataBytes
from hexbytes import HexBytes
from dataclasses import fields

from .contract_common import (
    InputJsonRpc,
    JSON_RPC,
    MessageParams,
    ParsedJsonRpc,
    ParsedMessage,
    ParsedTransaction,
    ParseError,
    RequiredParams,
    TransactionParams,
)


class ParamParser:
    """
    Base class for parsing JSON RPC request parameters.

    After instantiation, parse using the parse() method.
    """

    def str_to_bytes(self, data: str) -> HexBytes:
        try:
            hex_data = HexBytes(data)
        except Exception as e:
            raise ParseError(f"'{data}' has bad byte structure: {e}")
        return hex_data

    def get_params(self, json_rpc: InputJsonRpc) -> RequiredParams:
        """
        Fetch all required parameters out of a InputJsonRpc's 'params' attribute,
        and compile into a more structured RequiredParams object. Maintains each parameter
        in its original form, without additional parsing.

        Arguments:
            json_rpc: JSON RPC data containing a list of params

        Returns:
            structured object of unparsed parameters
        """
        raise NotImplementedError()

    def parse(self, json_rpc: InputJsonRpc) -> ParsedJsonRpc:
        """
        Fetch all required parameters out of an InputJsonRpc, and return a fully parsed
        version of the json rpc

        Arguments:
            json_rpc: JSON RPC data containing a list of params

        Returns:
            fully parsed json rpc
        """
        raise NotImplementedError()


class TransactionParser(ParamParser):
    """
    Parser for extracting data out of an eth_sendTransaction-style JSON RPC request's params.
    """

    def __init__(self, contracts: dict[bytes, Type[Contract]]) -> None:
        """
        Arguments:
            contracts: dictionary mapping known contract addresses to ABI information
        """
        self.contracts = contracts

    def get_params(self, json_rpc: InputJsonRpc) -> TransactionParams:
        if len(json_rpc.params) != 1:
            raise ParseError(
                "Invalid JSON RPC: transaction params must take exactly 1 object"
            )
        params = json_rpc.params[0]

        if "to" not in params or "data" not in params:
            raise ParseError(f"Invalid JSON RPC: params must contain 'to' and 'data'")

        return TransactionParams(to=params["to"], data=params["data"])

    def parse_transaction(
        self, json_rpc: InputJsonRpc, params: TransactionParams
    ) -> ParsedTransaction:
        """
        Arguments:
            json_rpc: JSON RPC data
            params: structured parameters

        Returns:
            fully parsed JSON RPC data
        """
        to = self.str_to_bytes(params.to)
        data = self.str_to_bytes(params.data)

        if to not in self.contracts:
            raise ParseError("not in list of known contracts")

        contract = self.contracts[to]
        try:
            method, args = contract.decode_function_input(data)
        except InsufficientDataBytes as e:
            raise ParseError(f"Bad args for contract method: {e}")

        return ParsedTransaction(
            eth_method=json_rpc.method,
            to=to,
            data=data,
            contract_type=contract,
            contract_method=method,
            contract_method_args=args,
        )

    def parse(self, json_rpc: InputJsonRpc) -> ParsedTransaction:
        params = self.get_params(json_rpc)
        parsed_transaction = self.parse_transaction(json_rpc, params)
        return parsed_transaction


class MessageParser(ParamParser):
    def __init__(self, message_index: int = 1) -> None:
        """
        Arguments:
            message_index: index in the json rpc parameters of the message.

        According to the JSON RPC's specification, eth_sign requests should specify
        the message to be signed as the second item in params (params[1]). However,
        personal_sign from geth's API instead places the message first (params[0]).
        """
        self.message_index = message_index

    def get_params(self, json_rpc: InputJsonRpc) -> MessageParams:
        if len(json_rpc.params) < self.message_index:
            raise ParseError(
                "More parameters expected for message-style JSON RPC requests"
            )
        message = json_rpc.params[self.message_index]
        return MessageParams(message=message)

    def parse_message(self, message: str) -> str:
        """
        Hex decode message into a plaintext string

        Arguments:
            message: string representation of hex-encoded data

        Returns:
            plaintext version of message

        """
        hex_str = self.str_to_bytes(message)
        text = hex_str.decode("ascii")
        return text

    def parse(self, json_rpc: InputJsonRpc) -> ParsedMessage:
        params = self.get_params(json_rpc)
        message = self.parse_message(params.message)
        return ParsedMessage(eth_method=json_rpc.method, message=message)


class Parser:
    def __init__(self, eth_method_parsers: dict[str, ParamParser]):
        self.eth_method_parsers = eth_method_parsers

    def raw_json_rpc_to_input(self, json_rpc: JSON_RPC) -> InputJsonRpc:
        """
        Convert raw json_rpc dictionary to an InputJsonRpc object.

        Args:
            json_rpc: raw JSON RPC information to convert

        Returns:
            An InputJsonRpc object containing the same information
        """

        args: dict[str, Any] = {}
        for field in fields(InputJsonRpc):
            if field.name not in json_rpc:
                raise ParseError(f"JSON RPC is missing required field '{field.name}'")
            args[field.name] = json_rpc[field.name]

        return InputJsonRpc(**args)

    def parse(self, json_rpc: JSON_RPC) -> ParsedJsonRpc:
        input_json_rpc = self.raw_json_rpc_to_input(json_rpc)

        method = input_json_rpc.method
        if method not in self.eth_method_parsers:
            raise ParseError(f"Eth method not recognized: {method}")

        return self.eth_method_parsers[method].parse(input_json_rpc)
