from typing import Any, Dict, List, Type
from web3.contract import Contract

from web3_policy_engine.contract_common import (
    MessageRequest,
    Request,
    TransactionRequest,
    InvalidPermissionsError,
    UnrecognizedRequestError,
    ArgumentGroup,
    Roles,
    ArgValue,
)


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

    def __init__(self, allowed_args: Dict[str, List[AllowedOption]]) -> None:
        self.allowed_args = allowed_args

    def verify_arg(self, arg_name: str, arg_value: ArgValue, user_roles: Roles) -> bool:
        if arg_name not in self.allowed_args:
            raise UnrecognizedRequestError(f"Unknown argument name '{arg_name}'")
        allowed_args_to_check = self.allowed_args[arg_name]
        result = [arg.verify(arg_value, user_roles) for arg in allowed_args_to_check]

        # if any allowed args are ok with the value, then it's good
        return any(result)

    def verify(self, request: TransactionRequest) -> bool:
        """Check if all arguments are allowed by at least one role the user has"""

        for arg_name, arg_value in request.transaction.args.items():
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
        allowed_methods: Dict[str, AllowedContractMethod],
    ) -> None:
        self.contract_type = contract_type
        self.allowed_methods = allowed_methods

    def get_method(self, request: TransactionRequest) -> AllowedContractMethod:
        """
        Get AllowedMethod object for the method specified in request.transaction
        """
        if request.transaction.method.fn_name in self.allowed_methods:
            return self.allowed_methods[request.transaction.method.fn_name]
        raise UnrecognizedRequestError("Method not found")

    def has_type(self, contract_type: Type[Contract]) -> bool:
        """Check if this object is associated with the specified contract type"""
        return contract_type == self.contract_type

    def verify(self, request: TransactionRequest) -> bool:
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
        allowed_contracts: List[AllowedContract],
    ) -> None:
        self.allowed_contracts = allowed_contracts

    def get_contract(self, request: TransactionRequest) -> AllowedContract:
        """
        Get the corresponding AllowedContract object for the contract type
        the user wants to use
        """
        for contract in self.allowed_contracts:
            if contract.has_type(request.transaction.contractType):
                return contract
        raise UnrecognizedRequestError("Contract type not recognized")

    def verify_transaction_request(self, request: TransactionRequest) -> bool:
        """
        Verify a transaction (used for eth_signTransaction or eth_sendTransaction)
        """
        contract = self.get_contract(request)
        return contract.verify(request)

    def verify(self, request: Request) -> bool:
        if not isinstance(request, TransactionRequest):
            raise UnrecognizedRequestError(
                "Expected an eth method which attempts to interact with a contract"
            )
        return self.verify_transaction_request(request)


class AllowedEthMessageMethod(AllowedEthMethod):
    def __init__(
        self,
        allowed_messages: List[AllowedOption],
    ) -> None:
        self.allowed_messages = allowed_messages

    def verify_message_request(self, request: MessageRequest) -> bool:
        """
        Verify a message (used for eth_sign or personal_sign)
        """
        allowed_message_results = [
            message.verify(request.message, request.roles)
            for message in self.allowed_messages
        ]

        if any(allowed_message_results):
            return True

        raise InvalidPermissionsError(
            f"message {request.message} not allowed for any role."
        )

    def verify(self, request: Request) -> bool:
        if not isinstance(request, MessageRequest):
            raise UnrecognizedRequestError(
                "Expected an eth method which takes a message as input"
            )
        return self.verify_message_request(request)


class Verifier:
    """
    Highest-level verifier. Examine a (parsed) request by a user,
    and decides if the user has the required permissions.
    """

    def __init__(self, allowed_eth_methods: Dict[str, AllowedEthMethod]) -> None:
        self.allowed_eth_methods = allowed_eth_methods

    def verify(self, request: Request) -> bool:
        """
        Verify a user request
        """
        if request.eth_method not in self.allowed_eth_methods:
            raise UnrecognizedRequestError("eth method not recognized")
        return self.allowed_eth_methods[request.eth_method].verify(request)
