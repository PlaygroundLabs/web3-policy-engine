from typing import Any, Type
import yaml
from web3.contract import Contract

from web3_policy_engine.contract_common import (
    TransactionRequest,
    InvalidPermissionsError,
    UnrecognizedRequestError,
    ArgumentGroup,
)


class AllowedArg:
    """Low-level verifier for arguments"""

    def __init__(self, options: list[Any], group_options: list[ArgumentGroup]) -> None:
        self.options = options
        self.group_options = group_options

    def verify_option(self, value: Any) -> bool:
        """Check if the value is in the list of allowed options"""
        return value in self.options

    def verify_groups(self, value: Any) -> list[bool]:
        """Check if the value is included in any of the allowed groups"""
        return [group.contains(value) for group in self.group_options]

    def verify(self, value: Any) -> bool:  # value can be any type used in solidity
        """Check if value is valid or not"""
        return self.verify_option(value) or any(self.verify_groups(value))


class AllowedRole:
    """Low-level verifier for roles"""

    def __init__(self, allowed_args: dict[str, AllowedArg]) -> None:
        self.allowed_args = allowed_args

    def verify_arg(self, arg_name: str, arg_value: Any) -> bool:
        """Check if the specified argument is allowed to have specified value"""
        if arg_name not in self.allowed_args:
            # if a role doesn't mention an argument, all values should be allowed
            return True

        allowed_arg = self.allowed_args[arg_name]
        return allowed_arg.verify(arg_value)


class AllowedMethod:
    """Low-level verifier for contract methods"""

    def __init__(self, allowed_roles: dict[str, AllowedRole]) -> None:
        self.allowed_roles = allowed_roles

    def verify_arg_all_roles(
        self, request: TransactionRequest, arg_name: str, arg_value: Any
    ) -> list[bool]:
        """For each role given, check if specified argument is allowed"""
        return [
            self.allowed_roles[role].verify_arg(arg_name, arg_value)
            for role in request.roles
            if role in self.allowed_roles
        ]

    def verify(self, request: TransactionRequest) -> bool:
        """Check if all arguments are allowed by at least one role the user has"""
        for arg_name, arg_value in request.transaction.args.items():
            allowed_roles = self.verify_arg_all_roles(request, arg_name, arg_value)
            if not any(allowed_roles):
                raise InvalidPermissionsError(
                    f"Argument {arg_name}={arg_value} not allowed for any role"
                )
        return True


class AllowedContract:
    """Verifier for smart contracts"""

    def __init__(
        self, contract_type: Type[Contract], allowed_methods: dict[str, AllowedMethod]
    ) -> None:
        self.contract_type = contract_type
        self.allowed_methods = allowed_methods

    def get_method(self, request: TransactionRequest) -> AllowedMethod:
        """
        Get AllowedMethod object for the method specified in request.transaction
        """
        if request.transaction.method.fn_name in self.allowed_methods.keys():
            return self.allowed_methods[request.transaction.method.fn_name]
        raise UnrecognizedRequestError("Method not found")

    def has_type(self, contract_type: Type[Contract]) -> bool:
        """Check if this object is associated with the specified contract type"""
        return contract_type == self.contract_type

    def verify(self, request: TransactionRequest) -> bool:
        """Verify that the transaction is valid for this contract"""
        method = self.get_method(request)
        return method.verify(request)


class Verifier:
    """
    Highest-level verifier. Examine a (parsed) request by a user,
    and decides if the user has the required permissions.
    """

    def __init__(self, allowed_contracts: list[AllowedContract]) -> None:
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

    def verify(self, request: TransactionRequest) -> bool:
        """
        Verify that the request is valid
        (i.e. the specified roles grant the required permissions to complete the transaction).
        Either returns True or raises an error.
        """
        contract = self.get_contract(request)
        return contract.verify(request)


def isolate_options_and_group_options(
    options: list[Any], groups: dict[str, ArgumentGroup]
) -> tuple[list[Any], list[ArgumentGroup]]:
    """
    Helper function for permissions_from_dict.
    Take a list of argument options as specified in a config file, and
    separates them into options (e.g. "1"), and groups (e.g. "managers")
    """
    return (
        [option for option in options if option not in groups.keys()],
        [group for group_name, group in groups.items() if group_name in options],
    )


def permissions_from_dict(
    data: dict[str, dict[str, list[dict[str, dict[str, list[Any]]]]]],
    contracts: dict[str, Type[Contract]],
    groups: dict[str, ArgumentGroup] = {},
) -> Verifier:
    """
    Load in a verifier object from a dictionary.
    Typically used to load from a config file (e.g. yaml, json)
    """

    for contract_name in data.keys():
        if contract_name not in contracts.keys():
            raise ValueError(f"Unknown contract: {contract_name}")

    verifier = Verifier(
        [
            AllowedContract(
                contracts[contract],
                {
                    method_name: AllowedMethod(
                        {
                            role_name: AllowedRole(
                                {
                                    arg_name: AllowedArg(
                                        *isolate_options_and_group_options(
                                            options, groups
                                        ),
                                    )
                                    for arg_name, options in args.items()
                                },
                            )
                            for role in roles
                            for role_name, args in role.items()
                        },
                    )
                    for method_name, roles in methods.items()
                },
            )
            for contract, methods in data.items()
            if contract in contracts
        ]
    )
    return verifier


def permissions_from_yaml(
    filename: str,
    contracts: dict[str, Type[Contract]],
    groups: dict[str, ArgumentGroup] = {},
) -> Verifier:
    """Load a Verifier object from a yaml file"""
    with open(filename, "r") as file_handle:
        data = yaml.safe_load(file_handle)
        return permissions_from_dict(data, contracts, groups)
