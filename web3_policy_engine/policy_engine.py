from .verify_permissions import permissions_from_yaml
from .parse_transaction import Parser
from .contract_common import (
    InputTransaction,
    contract_addresses_from_json,
    argument_groups_from_yaml,
    TransactionRequest,
)


class PolicyEngine:
    """
    High-level interface for interacting with the policy engine.
    TODO: make this more general, allowing alternative input types (eventually databases)
    """

    def __init__(
        self, contract_addresses: str, permissions_config: str, argument_groups: str
    ) -> None:
        contracts, addresses = contract_addresses_from_json(contract_addresses)
        self.parser = Parser(addresses)
        groups = argument_groups_from_yaml(argument_groups)
        self.verifier = permissions_from_yaml(permissions_config, contracts, groups)
    
    # TODO: make load_from_file classmethod

    def verify(self, transaction: InputTransaction, roles: list[str]) -> bool:
        """
        Parse the raw transaction, and then verify that the specified roles grant
        permission to execute it.
        """
        parsed_transaction = self.parser.parse(transaction)
        request = TransactionRequest(parsed_transaction, roles)
        return self.verifier.verify(request)
