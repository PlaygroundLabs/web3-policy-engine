from .loader import (
    permissions_from_yaml,
    contract_addresses_from_json,
    argument_groups_from_yaml,
)
from .parse_transaction import Parser
from .contract_common import (
    InputTransaction,
    MessageRequest,
    TransactionRequest,
    ArgumentGroup,
)

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

    def verify_transaction(
        self, eth_method: str, to: str, data: str, roles: list[str]
    ) -> bool:
        """
        Parse raw transaction, and then verify that the specified roles grant
        permission to execute it.
        """
        transaction = InputTransaction(to, data)
        parsed_transaction = self.parser.input_transaction_to_parsed_transaction(transaction)
        request = TransactionRequest(parsed_transaction, eth_method, roles)
        return self.verifier.verify(request)

    def verify_message(self, eth_method: str, message: str, roles: list[str]) -> bool:
        """
        Parse message, and then verify that the specified roles grant permission
        to sign it
        """
        parsed_message = self.parser.parse_message(message)
        request = MessageRequest(parsed_message, eth_method, roles)
        return self.verifier.verify(request)
