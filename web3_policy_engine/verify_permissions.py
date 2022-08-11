from typing import Any, Type
from web3.contract import Contract

from web3_policy_engine.contract_common import (
    ParsedMessage,
    ParsedTransaction,
    Request,
    InvalidPermissionsError,
    UnrecognizedRequestError,
    ArgumentGroup,
    Roles,
    ArgValue,
)


def get_transaction_json_rpc(request: Request) -> ParsedTransaction:
    json_rpc = request.json_rpc
    if not isinstance(json_rpc, ParsedTransaction):
        raise UnrecognizedRequestError(
            "Expected an eth method which attempts to interact with a contract"
        )
    return json_rpc


def get_message_json_rpc(request: Request) -> ParsedMessage:
    json_rpc = request.json_rpc
    if not isinstance(json_rpc, ParsedMessage):
        raise UnrecognizedRequestError(
            "Expected an eth method which attempts to sign a message"
        )
    return json_rpc


class AllowedOption:
    def __init__(self, option: Any, allowed_roles: Roles) -> None:
        self.option = option
        self.allowed_roles = allowed_roles

    def verify_value(self, value: ArgValue) -> bool:
        raise NotImplementedError()

    def verify_roles(self, user_roles: Roles) -> bool:
        return any([role in self.allowed_roles for role in user_roles])

    def verify(self, value: ArgValue, user_roles: Roles) -> bool:
        return self.verify_value(value) and self.verify_roles(user_roles)


class AllowedValue(AllowedOption):
    def __init__(self, value: ArgValue, allowed_roles: Roles) -> None:
        super().__init__(value, allowed_roles)

    def verify_value(self, value: ArgValue) -> bool:
        return value == self.option


class AllowedGroup(AllowedOption):
    def __init__(self, group: ArgumentGroup, allowed_roles: Roles) -> None:
        super().__init__(group, allowed_roles)

    def verify_value(self, value: ArgValue) -> bool:
        return self.option.contains(value)


class AllowedContractMethod:
    """Low-level verifier for contract methods"""

    def __init__(self, allowed_args: dict[str, list[AllowedOption]]) -> None:
        self.allowed_args = allowed_args

    def verify_arg(self, arg_name: str, arg_value: ArgValue, user_roles: Roles) -> bool:
        if arg_name not in self.allowed_args:
            raise UnrecognizedRequestError(f"Unknown argument name '{arg_name}'")
        allowed_args_to_check = self.allowed_args[arg_name]
        result = [arg.verify(arg_value, user_roles) for arg in allowed_args_to_check]

        # if any allowed args are ok with the value, then it's good
        return any(result)

    def verify(self, request: Request) -> bool:
        """Check if all arguments are allowed by at least one role the user has"""

        json_rpc = get_transaction_json_rpc(request)

        args = json_rpc.contract_method_args
        for arg_name, arg_value in args.items():
            allowed = self.verify_arg(arg_name, arg_value, request.roles)

            if not allowed:
                raise InvalidPermissionsError(
                    f"Argument {arg_name}={arg_value} not allowed for any role"
                )
        return True


class AllowedContract:
    """Verifier for smart contracts"""

    def __init__(
        self,
        contract_type: Type[Contract],
        allowed_methods: dict[str, AllowedContractMethod],
    ) -> None:
        self.contract_type = contract_type
        self.allowed_methods = allowed_methods

    def get_method(self, request: Request) -> AllowedContractMethod:
        """
        Get AllowedMethod object for the method specified in request.transaction
        """
        json_rpc = get_transaction_json_rpc(request)
        method = json_rpc.contract_method.fn_name
        if method in self.allowed_methods:
            return self.allowed_methods[method]
        raise UnrecognizedRequestError("Method not found")

    def has_type(self, contract_type: Type[Contract]) -> bool:
        """Check if this object is associated with the specified contract type"""
        return contract_type == self.contract_type

    def verify(self, request: Request) -> bool:
        """Verify that the transaction is valid for this contract"""
        method = self.get_method(request)
        return method.verify(request)


class AllowedEthMethod:
    """
    Verifier for ethereum methods (e.g. eth_sendTransaction).
    Currently, only the following are supported:
        - sendTransaction
        - signTransaction
        - sign
        - personal_sign
    """

    def verify(self, request: Request) -> bool:
        """
        Verify that the request is valid
        (i.e. the specified roles grant the required permissions to sign the message).
        Either returns True or raises an error.
        """
        raise NotImplementedError()


class AllowedEthContractMethod(AllowedEthMethod):
    def __init__(
        self,
        allowed_contracts: list[AllowedContract],
    ) -> None:
        self.allowed_contracts = allowed_contracts

    def get_contract(self, request: Request) -> AllowedContract:
        """
        Get the corresponding AllowedContract object for the contract type
        the user wants to use
        """
        json_rpc = get_transaction_json_rpc(request)

        for contract in self.allowed_contracts:
            if contract.has_type(json_rpc.contract_type):
                return contract

        raise UnrecognizedRequestError("Contract type not recognized")

    def verify(self, request: Request) -> bool:
        """
        Verify a transaction (used for eth_signTransaction or eth_sendTransaction)
        """
        contract = self.get_contract(request)
        return contract.verify(request)


class AllowedEthMessageMethod(AllowedEthMethod):
    def __init__(
        self,
        allowed_messages: list[AllowedOption],
    ) -> None:
        self.allowed_messages = allowed_messages

    def get_message(self, request: Request) -> str:
        json_rpc = get_message_json_rpc(request)
        return json_rpc.message

    def verify(self, request: Request) -> bool:
        """
        Verify a message (used for eth_sign or personal_sign)
        """
        message = self.get_message(request)
        allowed_message_results = [
            allowed_message.verify(message, request.roles)
            for allowed_message in self.allowed_messages
        ]

        if any(allowed_message_results):
            return True

        raise InvalidPermissionsError(f"message '{message}' not allowed for any role.")


class Verifier:
    """
    Highest-level verifier. Examine a (parsed) request by a user,
    and decides if the user has the required permissions.
    """

    def __init__(self, allowed_eth_methods: dict[str, AllowedEthMethod]) -> None:
        self.allowed_eth_methods = allowed_eth_methods

    def verify(self, request: Request) -> bool:
        """
        Verify a user request
        """
        method = request.json_rpc.eth_method
        if method not in self.allowed_eth_methods:
            raise UnrecognizedRequestError("eth method not recognized")
        return self.allowed_eth_methods[method].verify(request)
