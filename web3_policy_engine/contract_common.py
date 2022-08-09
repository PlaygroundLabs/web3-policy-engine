from abc import ABC
from web3.contract import Contract, ContractFunction
from typing import Any, Type


# typedefs for commonly used things
Roles = list[str]
ArgValue = Any


class InputTransaction:
    """
    Defines all of the required information for transaction inputs to policy engine
    """

    def __init__(self, to: str, data: str):
        self.to = to
        self.data = data


class ParsedTransaction:
    """
    Everything that should be in a parsed transaction
    """

    def __init__(
        self,
        to: bytes,
        data: bytes,
        contractType: Type[Contract],
        method: ContractFunction,
        args: dict[str, ArgValue],
    ):
        self.to = to
        self.data = data
        self.contractType = contractType
        self.method = method
        self.args = args


class Request(ABC):
    """
    Base abstract Request class
    """

    def __init__(self, eth_method: str, roles: Roles) -> None:
        self.eth_method = eth_method
        self.roles = roles


class TransactionRequest(Request):
    """
    Complete request, with both transaction info and user role info
    """

    def __init__(
        self, transaction: ParsedTransaction, eth_method: str, roles: list[str]
    ) -> None:
        self.transaction = transaction
        super().__init__(eth_method, roles)


class MessageRequest(Request):
    """
    Wrapper for message requests, as used in sign or personal_sign
    """

    def __init__(self, message: str, eth_method: str, roles: list[str]) -> None:
        self.message = message
        super().__init__(eth_method, roles)


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
