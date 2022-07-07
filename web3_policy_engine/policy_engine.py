from .verify_permissions import permissions_from_yaml
from .parse_transaction import Parser
from .contract_common import InputTransaction, contract_addresses_from_json, Request


class PolicyEngine:
    def __init__(self, contract_addresses: str, permissions_config: str) -> None:
        contracts, addresses = contract_addresses_from_json(contract_addresses)
        self.parser = Parser(addresses)
        self.verifier = permissions_from_yaml(permissions_config, contracts)
    
    def verify(self, transaction : InputTransaction, roles: list[str]) -> bool:
        parsed_transaction = self.parser.parse(transaction)
        request = Request(parsed_transaction, roles)
        return self.verifier.verify(request)

