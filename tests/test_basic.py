from typing import Iterable, Type
from unittest import TestCase
from hexbytes import HexBytes
from web3.auto import w3
from web3.contract import Contract
from eth_abi.exceptions import InsufficientDataBytes

from web3_policy_engine.contract_common import (
    ArgValue,
    InputTransaction,
    MessageRequest,
    ParsedTransaction,
    Request,
    TransactionRequest,
    ArgumentGroup,
    ParseError,
    InvalidPermissionsError,
    UnrecognizedRequestError,
)
from web3_policy_engine.parse_transaction import Parser
from web3_policy_engine.policy_engine import PolicyEngine
from web3_policy_engine.verify_permissions import (
    AllowedContractMethod,
    AllowedContract,
    AllowedEthContractMethod,
    AllowedEthMessageMethod,
    AllowedGroup,
    AllowedValue,
    Verifier,
)

from web3_policy_engine.loader import (
    contract_from_json,
    method_signature,
    allowed_contracts_from_dict,
    permissions_from_yaml,
)


class TestContract(TestCase):
    def test_from_json(self):
        contract = contract_from_json("tests/data/abi/test_abi.json")
        self.assertEqual("testmethod1", contract.functions.testmethod1.fn_name)


class TestParser(TestCase):
    def test_transaction_basic(self):
        """Test parsing a transaction for a simple contract method with one input"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build valid raw transaction
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )
        transaction = InputTransaction(
            "0x1234123412341234123412341234123412341234", payload.hex()
        )

        res = parser.parse_transaction(transaction)
        self.assertEqual(res.contractType, contract)
        self.assertEqual(res.method.fn_name, "testmethod1")
        self.assertEqual(len(res.args.keys()), 1)
        self.assertEqual(res.args["_arg1"], 6)

    def test_transaction_multiple_args(self):
        """Test parsing a transaction for contract methods with several arguments"""
        contract = make_contract_multple_args(
            ["uint256", "address", "address", "uint256"]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build valid raw transaction
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        payload += HexBytes(
            "0x0000000000000000000000002222222222222222222222222222222222222222"
        )
        payload += HexBytes(
            "0x0000000000000000000000003333333333333333333333333333333333333333"
        )
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000004"
        )
        transaction = InputTransaction(
            "0x1234123412341234123412341234123412341234", payload.hex()
        )

        res = parser.parse_transaction(transaction)
        self.assertEqual(res.contractType, contract)
        self.assertEqual(res.method.fn_name, "testmethod1")
        self.assertEqual(len(res.args.keys()), 4)
        self.assertEqual(res.args["_arg1"], 1)
        self.assertEqual(
            res.args["_arg2"], "0x2222222222222222222222222222222222222222"
        )
        self.assertEqual(
            res.args["_arg3"], "0x3333333333333333333333333333333333333333"
        )
        self.assertEqual(res.args["_arg4"], 4)

        # build invalid raw transaction, has first argument, but no subsequent ones
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        transaction = InputTransaction(
            "0x1234123412341234123412341234123412341234", payload.hex()
        )
        self.assertRaises(ParseError, parser.parse_transaction, transaction)

    def test_transaction_invalid_contract(self):
        """Test parsing a transaction for an unrecognized contract"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build invalid raw transaction, no contract at address 0x2222...
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )
        transaction = InputTransaction(
            "0x2222222222222222222222222222222222222222", payload.hex()
        )

        self.assertRaises(ParseError, parser.parse_transaction, transaction)

    def test_transaction_invalid_method_name(self):
        """Test that the parser fails when given a method name which doesn't exist"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        transaction = InputTransaction(
            "0x1234123412341234123412341234123412341234",
            "0x343434340000000000000000000000000000000000000000000000000000000000000006",
        )
        self.assertRaises(ValueError, parser.parse_transaction, transaction)

    def test_transaction_no_method_args(self):
        """Test that the parser fails when no arguments are specified"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        payload = method_signature(contract.functions.testmethod1)
        transaction = InputTransaction(
            ("0x1234123412341234123412341234123412341234"), payload.hex()
        )
        self.assertRaises(ParseError, parser.parse_transaction, transaction)

    def test_message_basic(self):
        """Test basic functionality of parse_message"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        original_message = "testmessage"
        parsed_message = parser.parse_message(
            HexBytes(original_message.encode("ascii")).hex()
        )
        self.assertEqual(original_message, parsed_message)


class TestVerify(TestCase):
    def test_value(self):
        """Test basic functionality of AllowedValue (allowing a particular value to a set of roles, and rejecting all others)"""
        allowed_arg = AllowedValue(1, ["testRole1"])

        # valid value
        self.assertTrue(allowed_arg.verify(1, ["testRole1"]))

        self.assertFalse(allowed_arg.verify(1, ["testRole2"]))
        self.assertFalse(allowed_arg.verify(10, ["testRole1"]))

    def test_group(self):
        """Test grouping functionality of AllowedGroup (allowing an ArgumentGroup to a set of roles, and rejecting all others)"""
        allowed_arg = AllowedGroup(ArgumentGroup([1, 2]), ["testRole1"])

        # valid value, 1 is in group
        self.assertTrue(allowed_arg.verify(1, ["testRole1"]))
        # valid value, 2 is in group
        self.assertTrue(allowed_arg.verify(2, ["testRole1"]))

        # invalid role
        self.assertFalse(allowed_arg.verify(1, ["testRole2"]))
        # invalud value, 10 is not in group
        self.assertFalse(allowed_arg.verify(10, ["testRole1"]))

    def test_role_one_arg(self):
        """Basic role usage"""
        allowed_arg = AllowedGroup(ArgumentGroup([1, 2]), ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})

        # valid, _arg1=1 is allowed
        self.assertTrue(allowed_method.verify_arg("_arg1", 1, ["testRole1"]))

        # invalid, _arg1=10 is not allowed
        self.assertFalse(allowed_method.verify_arg("_arg1", 10, ["testRole1"]))

    def test_multiple_roles_multiple_args(self):
        """More complex role interactions"""
        allowed_arg1a = AllowedValue(1, ["testRole1"])
        allowed_arg1b = AllowedValue(2, ["testRole1", "testRole2"])
        allowed_arg2 = AllowedGroup(ArgumentGroup([10]), ["testRole2"])
        allowed_method = AllowedContractMethod(
            {"_arg1": [allowed_arg1a, allowed_arg1b], "_arg2": [allowed_arg2]}
        )

        # testRole1:
        # valid, _arg1=1 is allowed
        self.assertTrue(allowed_method.verify_arg("_arg1", 1, ["testRole1"]))
        # valid, _arg1=2 is allowed
        self.assertTrue(allowed_method.verify_arg("_arg1", 2, ["testRole1"]))
        # invalid, _arg1=10 is not allowed
        self.assertFalse(allowed_method.verify_arg("_arg1", 10, ["testRole1"]))
        # invalid, _arg2=1 not allowed
        self.assertFalse(allowed_method.verify_arg("_arg2", 1, ["testRole1"]))

        # testRole2:
        # invalid, _arg1 = 1 is not allowed
        self.assertFalse(allowed_method.verify_arg("_arg1", 1, ["testRole2"]))
        # valid, _arg1=2 is allowed
        self.assertTrue(allowed_method.verify_arg("_arg1", 2, ["testRole2"]))
        # valid, _arg2=10 is allowed
        self.assertTrue(allowed_method.verify_arg("_arg2", 10, ["testRole2"]))

        # testRole1 and testRole2
        # invalid, _arg1 = -1 is not allowed
        self.assertFalse(
            allowed_method.verify_arg("_arg1", -1, ["testRole1", "testRole2"])
        )
        # valid, _arg2 = 10 is allowed
        self.assertTrue(
            allowed_method.verify_arg("_arg2", 10, ["testRole1", "testRole2"])
        )

    def test_role_wrong_arg(self):
        """
        Test what happens if user provides an arg which isn't present in config.
        Current behavior is that the request will be treated as invalid
        """
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})

        # valid, _arg2 not specified, so allowed by default
        self.assertRaises(
            UnrecognizedRequestError,
            allowed_method.verify_arg,
            "_arg2",
            1,
            ["testRole1"],
        )

    def test_role_missing_arg(self):
        """
        Test what happens if user fails to provide an arg which is present in config.
        Current behavior is that the request will be treated as valid.

        NOTE: this situation shouldn't happen, because an error should be raised when a transaction
        that is missing an argument is parsed.
        """
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod(
            {"_arg1": [allowed_arg], "_arg2": [allowed_arg]}
        )

        # valid, _arg2 not specified, so allowed by default
        self.assertTrue(
            UnrecognizedRequestError,
            allowed_method.verify_arg("_arg2", 1, ["testRole1"]),
        )

    def test_method_verify(self):
        """Give an AllowedContractMethod a parsed transaction, and verify that it behaves as expected"""
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})

        contract = make_basic_contract()

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # failing transaction, no valid role
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    def test_method_multiple_args(self):
        """Test AllowedMethod with a contract method that takes multiple arguments"""
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod(
            {"_arg1": [allowed_arg], "_arg2": [allowed_arg]}
        )

        contract = make_contract_multple_args(["uint256", "uint256"])

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {"_arg1": 1, "_arg2": 1},
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, _arg2=10 not allowed for testRole1
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {"_arg1": 1, "_arg2": 10},
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    # def test_method_multiple_roles(self):
    #     """Test various combinations of roles with slightly different permissions on the same method"""
    #     allowed_arg1a = AllowedValue(1, ["testRole1"])
    #     allowed_arg1b = AllowedValue(2, ["testRole1"])
    #     allowed_arg2 = AllowedValue(10, ["testRole2"])
    #     allowed_method = AllowedContractMethod({"_arg1": [allowed_arg1a, allowed_arg1b], "_arg2": [allowed_arg2]})

    #     contract = make_contract_multple_args(["uint256", "uint256"])

    #     # valid transaction, one good role
    #     transaction = ParsedTransaction(
    #         HexBytes("0x1234123412341234123412341234123412341234"),
    #         HexBytes("0x0"),
    #         contract,
    #         contract.functions.testmethod1,
    #         {
    #             "_arg1": 1,
    #             "_arg2": 1,
    #         },
    #     )
    #     request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
    #     self.assertTrue(allowed_method.verify(request))

    #     # valid transaction, one bad role and one good one
    #     transaction = ParsedTransaction(
    #         HexBytes("0x1234123412341234123412341234123412341234"),
    #         HexBytes("0x0"),
    #         contract,
    #         contract.functions.testmethod1,
    #         {
    #             "_arg1": 10,
    #             "_arg2": 10,
    #         },
    #     )
    #     request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1", "testRole2"])
    #     self.assertTrue(allowed_method.verify(request))

    #     # invalid transaction, two bad roles
    #     transaction = ParsedTransaction(
    #         HexBytes("0x1234123412341234123412341234123412341234"),
    #         HexBytes("0x0"),
    #         contract,
    #         contract.functions.testmethod1,
    #         {
    #             "_arg1": -1,
    #             "_arg2": 10,
    #         },
    #     )
    #     request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
    #     self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    #     # valid transaction, _arg1=1 allowed by testRole1, and _arg1=10 allowed by testRole2
    #     transaction = ParsedTransaction(
    #         HexBytes("0x1234123412341234123412341234123412341234"),
    #         HexBytes("0x0"),
    #         contract,
    #         contract.functions.testmethod1,
    #         {
    #             "_arg1": 1,
    #             "_arg2": 10,
    #         },
    #     )
    #     request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1", "testRole2"])
    #     self.assertTrue(allowed_method.verify(request))

    def test_contract(self):
        """Test basic functionality of AllowedContract"""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])

        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})
        allowed_contract = AllowedContract(contract, {"testmethod1": allowed_method})

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(allowed_contract.verify(request))

        # failing transaction, no valid methods
        transaction = ParsedTransaction(
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_contract.verify, request)

    def test_eth_contract_method(self):
        """Test basic functionality of AllowedEthContractMethod"""
        contract = make_basic_contract()
        contract2 = make_basic_contract()
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})
        allowed_contract = AllowedContract(contract, {"testmethod1": allowed_method})
        allowed_eth_method = AllowedEthContractMethod([allowed_contract])

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(allowed_eth_method.verify(request))

        # failing transaction, wrong contract type
        transaction = ParsedTransaction(
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract2,
            contract2.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_eth_method.verify, request)

        # failing transaction, wrong request type
        request = MessageRequest("testmessage", "eth_sendTransaction", ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_eth_method.verify, request)

    def test_allowed_eth_message_method(self):
        """Test AllowedEthMessageMethod"""
        allowed_arg1 = AllowedValue("message1", ["testRole1"])
        allowed_message = AllowedEthMessageMethod([allowed_arg1])

        # valid request, testRole1 does have permission to sign "message1"
        request = MessageRequest("message1", "eth_sign", ["testRole1"])
        self.assertTrue(allowed_message.verify(request))

        # invalid request, testRole1 does not have permission to sign "submessage1"
        request = MessageRequest("submessage1", "eth_sign", ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_message.verify, request)

        request = Request("eth_sign", ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_message.verify, request)

    def test_verifier(self):
        """Test basic functionality of Verifier"""
        contract = make_basic_contract()
        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})
        allowed_contract = AllowedContract(contract, {"testmethod1": allowed_method})
        allowed_eth_method = AllowedEthContractMethod([allowed_contract])
        verifier = Verifier({"eth_sendTransaction": allowed_eth_method})

        # valid transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(verifier.verify(request))

        # invalid request, incorrect eth method
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_signTransaction", ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, verifier.verify, request)


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
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(permissions.verify_transaction_request(request))

        # invalid transaction, arg not allowed for testRole1
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": -1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertRaises(
            InvalidPermissionsError, permissions.verify_transaction_request, request
        )

        # invalid transaction, no perms for testRole2
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole2"])
        self.assertRaises(
            InvalidPermissionsError, permissions.verify_transaction_request, request
        )

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
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction, 10 is in group2
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # valid transaction, 10 is a single option
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
        self.assertTrue(permissions.verify(request))

        # invalid transaction, -1 is not in any group or value
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": -1,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
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
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 100,
            },
        )
        request = TransactionRequest(transaction, "eth_sendTransaction", ["testRole1"])
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
        testmethod1_sig = method_signature(
            policy_engine.parser.contracts[
                HexBytes(contract_address)
            ].functions.testmethod1
        )
        contract_address = "0x1234123412341234123412341234123412341234"

        # good transaction, testmethod1(_arg1=100) allowed for testRole1
        payload = testmethod1_sig + format_arg(100)
        self.assertTrue(
            policy_engine.verify_transaction(
                eth_method,
                contract_address,
                payload.hex(),
                ["testRole1"],
            ),
        )

        # bad transaction, testmethod1(_arg1=1) not allowed for testRole1
        payload = testmethod1_sig + format_arg(1)
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify_transaction,
            eth_method,
            contract_address,
            payload.hex(),
            ["testRole1"],
        )

        # bad transaction, testRole2 not allowed to use testmethod1
        payload = testmethod1_sig + format_arg(100)
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify_transaction,
            eth_method,
            contract_address,
            payload.hex(),
            ["testRole2"],
        )

        # good transaction, testRole2 not allowed to use testmethod1, but testRole1 is
        payload = testmethod1_sig + format_arg(100)
        self.assertTrue(
            policy_engine.verify_transaction(
                eth_method,
                contract_address,
                payload.hex(),
                ["testRole2", "testRole1"],
            )
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
        payload = (
            "0x9bfff434"
            + "0000000000000000000000000000000000000000000000000000000000000064"
            + "0000000000000000000000001212121212121212121212121212121212121212"
            + "0000000000000000000000001212121212121212121212121212121212121212"
        )
        self.assertTrue(
            policy_engine.verify_transaction(
                eth_method, contract_address, payload, ["testRole1"]
            )
        )

        # valid transaction, _arg1=100,arg2=3434... is allowed for testRole1
        payload = (
            "0x9bfff434"
            + "0000000000000000000000000000000000000000000000000000000000000064"
            + "0000000000000000000000003434343434343434343434343434343434343434"
        )
        self.assertTrue(
            policy_engine.verify_transaction(
                eth_method, contract_address, payload, ["testRole1"]
            )
        )

        # invalid transaction, _arg2 not allowed for testRole1 when _arg1 = 200
        payload = (
            "0x9bfff434"
            + "00000000000000000000000000000000000000000000000000000000000000C8"
            + "0000000000000000000000007878787878787878787878787878787878787878"
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify_transaction,
            eth_method,
            contract_address,
            payload,
            ["testRole1"],
        )

        # valid transaction, _arg2 is allowed when _arg1=100 for role testRole2
        payload = (
            "0x9bfff434"
            + "0000000000000000000000000000000000000000000000000000000000000064"
            + "0000000000000000000000007878787878787878787878787878787878787878"
        )
        self.assertTrue(
            policy_engine.verify_transaction(
                eth_method, contract_address, payload, ["testRole2"]
            )
        )

    def test_from_file_messages(self):
        policy_engine = PolicyEngine.from_file(
            "tests/data/test_contract_addresses.json",
            "tests/data/test_config.yml",
            "tests/data/test_groups.yml",
        )
        eth_method = "eth_sign"

        payload = str_to_hex("message1").hex()
        self.assertTrue(
            policy_engine.verify_message(eth_method, payload, ["testRole1"])
        )

        payload = str_to_hex("message1").hex()
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify_message,
            eth_method,
            payload,
            ["testRole2"],
        )


def make_basic_contract() -> Type[Contract]:
    """Construct a basic web3 contract with one method (taking a uint256 as input)"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                ],
                "name": "testmethod1",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
        ]
    )


def make_contract_multple_args(types: Iterable[str]) -> Type[Contract]:
    """Construct web3 contract with one method taking various input types"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {"internalType": "uint256", "name": f"_arg{i+1}", "type": arg_type}
                    for i, arg_type in enumerate(types)
                ],
                "name": "testmethod1",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
        ]
    )


def make_contract_multiple_methods(types: Iterable[Iterable[str]]) -> Type[Contract]:
    """Construct web3 contract with several methods all taking various input types"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {
                        "internalType": "uint256",
                        "name": f"_arg{arg_num+1}",
                        "type": arg_type,
                    }
                    for arg_num, arg_type in enumerate(method_types)
                ],
                "name": f"testmethod{method_num+1}",
                "outputs": [
                    {"internalType": "uint256", "name": "_out", "type": "uint256"}
                ],
                "payable": False,
                "stateMutability": "nonpayable",
                "type": "function",
            }
            for method_num, method_types in enumerate(types)
        ]
    )


def format_arg(arg: ArgValue) -> HexBytes:
    val = HexBytes(arg).hex()[2:]
    return HexBytes(f"0x{val:0>64}")


def str_to_hex(item: str) -> HexBytes:
    return HexBytes(bytes(item, "ascii"))
