from .verify_permissions import permissions_from_yaml
from .parse_transaction import Parser
from .contract_common import (
    InputTransaction,
    contract_addresses_from_json,
    argument_groups_from_yaml,
    TransactionRequest,
    ArgumentGroup,
)

from hexbytes import HexBytes
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
        self.parser = Parser(addresses)
        self.verifier = permissions_from_yaml(permissions_config, contracts, groups)

    @classmethod
    def from_file(
        cls, contract_addresses: str, permissions_config: str, argument_groups: str
    ):
        contracts, addresses = contract_addresses_from_json(contract_addresses)
        groups = argument_groups_from_yaml(argument_groups)
        return cls(contracts, addresses, groups, permissions_config)

    def verify(self, to: str, data: str, roles: list[str]) -> bool:
        """
        Parse the raw transaction, and then verify that the specified roles grant
        permission to execute it.
        """
        transaction = InputTransaction(HexBytes(to), HexBytes(data))
        parsed_transaction = self.parser.parse_transaction(transaction)
        request = TransactionRequest(parsed_transaction, roles)
        return self.verifier.verify(request)
