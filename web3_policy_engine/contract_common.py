from web3.contract import Contract, ContractFunction
from typing import Any, Type
from dataclasses import dataclass


# typedefs for commonly used things
Roles = list[str]
ArgValue = Any

JSON_RPC = dict[str, Any]


@dataclass
class InputJsonRpc:
    """
    Dataclass storing necessary information from a raw json rpc
    """

    method: str
    params: list[Any]


@dataclass
class RequiredParams:
    """
    Base dataclass for required attributes in a json rpc's "params" field
    """


@dataclass
class TransactionParams(RequiredParams):
    """
    Required parameters in a transaction-style json rpc request
    """

    to: str
    data: str


@dataclass
class MessageParams(RequiredParams):
    """
    Required parameters in a message-style json rpc request
    """

    message: str


@dataclass
class ParsedJsonRpc:
    """
    Base class for all parsed json rpcs
    """

    eth_method: str


@dataclass
class ParsedTransaction(ParsedJsonRpc):
    """
    Dataclass storing all important parsed attributes of a transaction-style JSON RPC request
    """

    to: bytes
    data: bytes
    contract_type: Type[Contract]
    contract_method: ContractFunction
    contract_method_args: dict[str, ArgValue]


@dataclass
class ParsedMessage(ParsedJsonRpc):
    """
    Dataclass storing all important parsed  attributes of a message-style JSON RPC request
    """

    message: str


@dataclass
class Request:
    """
    Base abstract Request class
    """

    json_rpc: ParsedJsonRpc
    roles: Roles


# class MessageRequest(Request):
#     """
#     Request class for message-style JSON RPC calls
#     """

#     json_rpc: ParsedMessage


# class TransactionRequest(Request):
#     """
#     Request class for message-style JSON RPC calls
#     """

#     json_rpc: ParsedTransaction


class ArgumentGroup:
    """
    Set of smart contract arguments grouped together into one ArgumentGroup. Used for large and/or frequently altered lists of arguments which should be associated with the
    same permissions.
    """

    def __init__(self, members: list[ArgValue]) -> None:
        """
        Basic initializer, which stores a list of items in the group
        :param members: list of recognized values in this group
        :type members: list[ArgValue]
        """
        self.members = members

    def contains(self, item: ArgValue) -> bool:
        """
        Check if specified item is in this group or not.

        :param item: item to check
        :type item: ArgValue
        :returns: *true* if this group contains item, else *false*
        :rtype: bool
        """
        return item in self.members


class PolicyEngineError(Exception):
    """Exception raised while verifying requests"""


class ParseError(PolicyEngineError):
    """Exception raised during parsing"""


class InvalidPermissionsError(PolicyEngineError):
    """Exception raised when the user doesn't have the required permissions"""


class UnrecognizedRequestError(PolicyEngineError):
    """Exception raised when request has an unrecognized method, contract type, etc."""
