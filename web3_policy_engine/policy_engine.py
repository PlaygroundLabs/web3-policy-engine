from .loader import (
    argument_groups_from_yaml,
    contract_addresses_from_json,
    permissions_from_yaml,
)
from .parse_transaction import make_basic_parser
from .contract_common import ArgumentGroup, JSON_RPC, Request

from typing import Type
from web3.contract import Contract


class PolicyEngine:
    """
    High-level interface for interacting with the policy engine.
    TODO: make this more general, allowing alternative input types (eventually databases)
    """

    def __init__(
        self,
        contracts: dict[str, Type[Contract]],
        addresses: dict[bytes, Type[Contract]],
        groups: dict[str, ArgumentGroup],
        permissions_config: str,
    ) -> None:
        self.parser = make_basic_parser(addresses)
        self.verifier = permissions_from_yaml(permissions_config, contracts, groups)

    @classmethod
    def from_file(
        cls, contract_addresses: str, permissions_config: str, argument_groups: str
    ):
        contracts, addresses = contract_addresses_from_json(contract_addresses)
        groups = argument_groups_from_yaml(argument_groups)

        return cls(contracts, addresses, groups, permissions_config)

    def verify(self, json_rpc: JSON_RPC, roles: list[str]) -> bool:
        parsed_transaction = self.parser.parse(json_rpc)
        request = Request(parsed_transaction, roles)
        return self.verifier.verify(request)
