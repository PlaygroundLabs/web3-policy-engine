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
    def __init__(self, options: list[Any], group_options: list[ArgumentGroup]) -> None:
        self.options = options
        self.group_options = group_options

    def verify(self, value: Any) -> bool:
        if value in self.options:
            return True
        if any([group.contains(value) for group in self.group_options]):
            return True
        return False


class AllowedRole:
    def __init__(self, allowed_args: dict[str, AllowedArg]) -> None:
        self.allowed_args = allowed_args

    def verify_arg(self, arg_name: str, arg_value: Any):
        if arg_name not in self.allowed_args:
            # TODO: consider changing this
            # if a role doesn't mention an argument at all, it should default to allowing anything.
            return True
        return self.allowed_args[arg_name].verify(arg_value)

    # def verify(self, request: Request) -> bool:
    #     if self.name not in request.roles:
    #         return False
    #     return all([arg.verify(request) for arg in self.allowed_args])


class AllowedMethod:
    def __init__(self, allowed_roles: dict[str, AllowedRole]) -> None:
        self.allowed_roles = allowed_roles

    def verify_arg_all_roles(
        self, request: TransactionRequest, arg_name: str, arg_value: Any
    ) -> list[bool]:
        return [
            self.allowed_roles[role].verify_arg(arg_name, arg_value)
            for role in request.roles
            if role in self.allowed_roles
        ]

    def verify(self, request: TransactionRequest) -> bool:
        # check if each arg is allowed by some role
        for arg_name, arg_value in request.transaction.args.items():
            if not any(self.verify_arg_all_roles(request, arg_name, arg_value)):
                raise InvalidPermissionsError(
                    f"Argument {arg_name}={arg_value} not allowed for any role"
                )
        return True

        # if any([role.verify(request) for role in self.allowed_roles]):
        #     return True

        # raise InvalidPermissionsError("User has no valid roles")


class AllowedContract:
    def __init__(
        self, contract_type: Type[Contract], allowed_methods: dict[str, AllowedMethod]
    ) -> None:
        self.contract_type = contract_type
        self.allowed_methods = allowed_methods

    def get_method(self, request: TransactionRequest) -> AllowedMethod:
        if request.transaction.method.fn_name in self.allowed_methods:
            return self.allowed_methods[request.transaction.method.fn_name]
        raise UnrecognizedRequestError("Method not found")
    
    def is_matching_contract(self, request: TransactionRequest) -> bool:
        return request.transaction.contractType == self.contract_type

    def verify(self, request: TransactionRequest) -> bool:
        method = self.get_method(request)
        return method.verify(request)


class Verifier:
    def __init__(self, allowed_contracts: list[AllowedContract]) -> None:
        self.allowed_contracts = allowed_contracts
    
    def get_contract(self, request: TransactionRequest) -> AllowedContract:
        for contract in self.allowed_contracts:
            if contract.is_matching_contract(request):
                return contract
        raise UnrecognizedRequestError("Contract type not recognized")

    def verify(self, request: TransactionRequest) -> bool:
        contract = self.get_contract(request)
        return contract.verify(request)


def isolate_options_and_group_options(
    options: list[Any], groups: dict[str, ArgumentGroup]
) -> tuple[list[Any], list[ArgumentGroup]]:
    return (
        [option for option in options if option not in groups.keys()],
        [group for group_name, group in groups.items() if group_name in options],
    )


def permissions_from_dict(
    data: dict[str, dict[str, list[dict[str, dict[str, list[Any]]]]]],
    contracts: dict[str, Type[Contract]],
    groups: dict[str, ArgumentGroup] = {},
) -> Verifier:

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
    with open(filename, "r") as file_handle:
        data = yaml.safe_load(file_handle)
        return permissions_from_dict(data, contracts, groups)
