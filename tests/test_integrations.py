from unittest import TestCase

from hexbytes import HexBytes
from web3_policy_engine.loader import (
    contract_from_json,
    allowed_contracts_from_dict,
    method_signature,
    permissions_from_yaml,
)
from web3_policy_engine.contract_common import (
    JSON_RPC,
    ArgValue,
    ArgumentGroup,
    InputJsonRpc,
    InvalidPermissionsError,
    ParsedTransaction,
    Request,
)
from web3_policy_engine.parse_transaction import TransactionParser
from web3_policy_engine.policy_engine import PolicyEngine

from .utils_for_tests import make_contract_multiple_methods, format_arg, str_to_hex


class TestContract(TestCase):
    def test_from_json(self):
        contract = contract_from_json("tests/data/abi/test_abi.json")
        self.assertEqual("testmethod1", contract.functions.testmethod1.fn_name)


class TestLoader(TestCase):
    def test_allowed_contracts_from_dict_bad_contract(self):
        """Test that allowed_contracts_from_dict throws exception when given an unrecognized contract"""
        contracts = {}
        data = {
            "testContract": {
                "testmethod1": {"_arg1": {1: ["testRole1"], 2: ["testRole1"]}},
                "testmethod2": {"_arg1": {10: ["testRole1"]}},
            }
        }
        self.assertRaises(ValueError, allowed_contracts_from_dict, data, contracts)

    def test_allowed_contracts_from_dict(self):
        """Test that user can load contracts from a dictionary."""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])
        contracts = {"testContract": contract}
        data = {
            "testContract": {
                "testmethod1": {"_arg1": {1: ["testRole1"], 2: ["testRole1"]}},
                "testmethod2": {"_arg1": {10: ["testRole1"]}},
            }
        }
        permissions = allowed_contracts_from_dict(data, contracts)

        # valid transaction
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # invalid transaction, arg not allowed for testRole1
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": -1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)

        # invalid transaction, no perms for testRole2
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole2"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)

    def test_allowed_contracts_from_dict_group(self):
        """Test that user can load a Verifier object from a dictionary, and that it works as expected."""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])
        contracts = {"testContract": contract}
        data = {
            "testContract": {
                "testmethod1": {
                    "_arg1": {"group1": ["testRole1"], "group2": ["testRole1"]}
                },
                "testmethod2": {"_arg1": {"group1": ["testRole1"], 10: ["testRole1"]}},
            }
        }
        groups = {"group1": ArgumentGroup([1, 2, 3]), "group2": ArgumentGroup([10, 20])}
        permissions = allowed_contracts_from_dict(data, contracts, groups)

        # valid transaction, 1 is in group1
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction, 10 is in group2
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction, 10 is a single option
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # invalid transaction, -1 is not in any group or value
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": -1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)

    def test_permissions_from_yaml(self):
        """Load a Verifier object from yaml"""
        contract = make_contract_multiple_methods([["uint256"], ["uint256", "address"]])
        contracts = {"testContract": contract}
        groups = {"group1": ArgumentGroup([1, 2, 3]), "group2": ArgumentGroup([10, 20])}
        permissions = permissions_from_yaml(
            "tests/data/test_config.yml", contracts, groups
        )

        # valid transaction, 100 is a single option
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 100,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(permissions.verify(request))

    def test_permissions_from_yaml_invalid(self):
        """Verify that invalid yaml files will throw an exception"""
        contract = make_contract_multiple_methods([["uint256"], ["uint256", "address"]])
        contracts = {"testContract": contract}
        groups = {"group1": ArgumentGroup([1, 2, 3]), "group2": ArgumentGroup([10, 20])}
        self.assertRaises(
            ValueError,
            permissions_from_yaml,
            "tests/data/test_config_invalid.yml",
            contracts,
            groups,
        )


class TestPolicyEngine(TestCase):
    def build_tx_json_rpc(
        self,
        policy_engine: PolicyEngine,
        eth_method: str,
        contract_address: str,
        contract_method: str,
        args: list[ArgValue],
    ) -> JSON_RPC:
        if eth_method not in policy_engine.parser.eth_method_parsers:
            raise ValueError("Bad eth method in test")

        send_tx_parser = policy_engine.parser.eth_method_parsers[eth_method]
        if not isinstance(send_tx_parser, TransactionParser):
            raise ValueError("Bad eth method in test")

        contract = send_tx_parser.contracts[HexBytes(contract_address)]

        sig = method_signature(contract.get_function_by_name(contract_method))

        payload_hex = sig
        for arg in args:
            payload_hex += format_arg(arg)
        payload = payload_hex.hex()

        json_rpc = {
            "method": eth_method,
            "params": [
                {
                    "to": contract_address,
                    "data": payload,
                    "from": "0x1111111111111111111111111111111111111111",
                }
            ],
            "json_rpc": "2.0",
            "id": 1,
        }
        return json_rpc

    def test_from_file_basic(self):
        """Test that you can load a policy engine from file, and that it works as expected"""
        # set up policy engine
        policy_engine = PolicyEngine.from_file(
            "tests/data/test_contract_addresses.json",
            "tests/data/test_config.yml",
            "tests/data/test_groups.yml",
        )
        contract_address = "0x1234123412341234123412341234123412341234"
        eth_method = "eth_sendTransaction"

        # good transaction, testmethod1(_arg1=100) allowed for testRole1
        json_rpc = self.build_tx_json_rpc(
            policy_engine, eth_method, contract_address, "testmethod1", [100]
        )
        self.assertTrue(
            policy_engine.verify(json_rpc, ["testRole1"]),
        )

        # bad transaction, testmethod1(_arg1=1) not allowed for testRole1
        json_rpc = self.build_tx_json_rpc(
            policy_engine, eth_method, contract_address, "testmethod1", [1]
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            json_rpc,
            ["testRole1"],
        )

        # bad transaction, testRole2 not allowed to use testmethod1
        json_rpc = self.build_tx_json_rpc(
            policy_engine, eth_method, contract_address, "testmethod1", [1]
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            json_rpc,
            ["testRole2"],
        )

        # good transaction, testRole2 not allowed to use testmethod1, but testRole1 is
        json_rpc = self.build_tx_json_rpc(
            policy_engine, eth_method, contract_address, "testmethod1", [1]
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            json_rpc,
            ["testRole2", "testRole1"],
        )

    def test_from_file_groups(self):
        # set up policy engine
        policy_engine = PolicyEngine.from_file(
            "tests/data/test_contract_addresses.json",
            "tests/data/test_config.yml",
            "tests/data/test_groups.yml",
        )
        contract_address = "0x1234123412341234123412341234123412341234"
        eth_method = "eth_sendTransaction"

        # testmethod2 requires a uint256 and an address

        # valid transaction, _arg1=100, arg2=0x1212... is allowed for testRole1
        json_rpc = self.build_tx_json_rpc(
            policy_engine,
            eth_method,
            contract_address,
            "testmethod2",
            [
                100,
                "0x1212121212121212121212121212121212121212",
            ],
        )
        self.assertTrue(policy_engine.verify(json_rpc, ["testRole1"]))

        # valid transaction, _arg1=100,arg2=3434... is allowed for testRole1
        json_rpc = self.build_tx_json_rpc(
            policy_engine,
            eth_method,
            contract_address,
            "testmethod2",
            [
                100,
                "0x3434343434343434343434343434343434343434",
            ],
        )
        self.assertTrue(policy_engine.verify(json_rpc, ["testRole1"]))

        # invalid transaction, _arg2 not allowed for testRole1 when _arg1 = 200
        json_rpc = self.build_tx_json_rpc(
            policy_engine,
            eth_method,
            contract_address,
            "testmethod2",
            [
                200,
                "0x7878787878787878787878787878787878787878",
            ],
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            json_rpc,
            ["testRole1"],
        )

        # valid transaction, _arg2 is allowed when _arg1=100 for role testRole2
        json_rpc = self.build_tx_json_rpc(
            policy_engine,
            eth_method,
            contract_address,
            "testmethod2",
            [
                100,
                "0x7878787878787878787878787878787878787878",
            ],
        )
        self.assertTrue(policy_engine.verify(json_rpc, ["testRole2"]))

    def test_from_file_messages(self):
        policy_engine = PolicyEngine.from_file(
            "tests/data/test_contract_addresses.json",
            "tests/data/test_config.yml",
            "tests/data/test_groups.yml",
        )
        eth_method = "eth_sign"

        # valid request, testRole1 does have permission to sign "message1"
        payload = str_to_hex("message1").hex()
        json_rpc = {
            "method": eth_method,
            "params": [
                "0x1111111111111111111111111111111111111111",
                payload,
            ],
            "json_rpc": "2.0",
            "id": 1,
        }
        self.assertTrue(policy_engine.verify(json_rpc, ["testRole1"]))

        # invalid request, testRole2 does not have permission to sign "message1"
        payload = str_to_hex("message1").hex()
        json_rpc = {
            "method": eth_method,
            "params": [
                "0x1111111111111111111111111111111111111111",
                payload,
            ],
            "json_rpc": "2.0",
            "id": 1,
        }
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            json_rpc,
            ["testRole2"],
        )
