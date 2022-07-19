from typing import Any, Type
import yaml
from web3.contract import Contract

from web3_policy_engine.contract_common import (
    Request,
    InvalidPermissionsError,
    UnrecognizedRequestError,
    ArgumentGroup,
)


class AllowedArg:
    def __init__(
        self, name: str, options: list[Any], group_options: list[ArgumentGroup]
    ) -> None:
        self.name = name
        self.options = options
        self.group_options = group_options

    def verify(self, request: Request) -> bool:
        if self.name not in request.transaction.args.keys():
            return False
        arg = request.transaction.args[self.name]
        if request.transaction.args[self.name] in self.options:
            return True
        for group in self.group_options:
            if group.contains(arg):
                return True
        return False


class AllowedRole:
    def __init__(self, name: str, allowed_args: list[AllowedArg]) -> None:
        self.name = name
        self.allowed_args = allowed_args

    def verify(self, request: Request) -> bool:
        if self.name not in request.roles:
            return False
        return all([arg.verify(request) for arg in self.allowed_args])


class AllowedMethod:
    def __init__(self, name: str, allowed_roles: list[AllowedRole]) -> None:
        self.name = name
        self.allowed_roles = allowed_roles

    def check_name(self, request: Request) -> bool:
        return request.transaction.method.fn_name == self.name

    def verify(self, request: Request) -> bool:
        if not self.check_name(request):
            # Should be unreachable in normal flow
            raise UnrecognizedRequestError("Method name not recognized")

        if any([role.verify(request) for role in self.allowed_roles]):
            return True

        raise InvalidPermissionsError("User has no valid roles")


class AllowedContract:
    def __init__(
        self, contract_type: Type[Contract], allowed_methods: list[AllowedMethod]
    ) -> None:
        self.contract_type = contract_type
        self.allowed_methods = allowed_methods

    def get_method(self, request: Request) -> AllowedMethod:
        for method in self.allowed_methods:
            if method.check_name(request):
                return method
        raise UnrecognizedRequestError("Method not found")

    def verify(self, request: Request) -> bool:
        if request.transaction.contractType != self.contract_type:
            raise UnrecognizedRequestError("Contract type not recognized")
        method = self.get_method(request)
        return method.verify(request)


class Verifier:
    def __init__(self, allowed_contracts: list[AllowedContract]) -> None:
        self.allowed_contracts = allowed_contracts

    def verify(self, request: Request) -> bool:
        return any([address.verify(request) for address in self.allowed_contracts])


def isolate_options_and_group_options(
    options: list[Any], groups: dict[str, ArgumentGroup]
) -> tuple[list[Any], list[ArgumentGroup]]:
    return (
        [option for option in options if option not in groups.keys()],
        [group for group_name, group in groups.items() if group_name in options]
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
                [
                    AllowedMethod(
                        method_name,
                        [
                            AllowedRole(
                                role_name,
                                [
                                    AllowedArg(
                                        arg_name,
                                        *isolate_options_and_group_options(
                                            options, groups
                                        ),
                                    )
                                    for arg_name, options in args.items()
                                ],
                            )
                            for role in roles
                            for role_name, args in role.items()
                        ],
                    )
                    for method_name, roles in methods.items()
                ],
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
