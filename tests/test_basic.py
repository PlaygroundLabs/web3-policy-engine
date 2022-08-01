from typing import Iterable, Type
from unittest import TestCase
from hexbytes import HexBytes
from web3.auto import w3
from web3.contract import Contract
from eth_abi.exceptions import InsufficientDataBytes

from web3_policy_engine.contract_common import (
    InputTransaction,
    ParsedTransaction,
    contract_from_json,
    method_signature,
    TransactionRequest,
    ArgumentGroup,
    InvalidPermissionsError,
    UnrecognizedRequestError,
)
from web3_policy_engine.parse_transaction import Parser
from web3_policy_engine.policy_engine import PolicyEngine
from web3_policy_engine.verify_permissions import (
    AllowedArg,
    AllowedMethod,
    AllowedRole,
    AllowedContract,
    Verifier,
    permissions_from_dict,
)


class TestContract(TestCase):
    def test_from_json(self):
        contract = contract_from_json("tests/data/abi/test_abi.json")
        self.assertEqual("testmethod1", contract.functions.testmethod1.fn_name)


class TestParser(TestCase):
    def test_basic(self):
        """Test parsing a transaction for a simple contract method with one input"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build valid raw transaction
        payload = method_signature(contract.functions.testMethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )
        transaction = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )

        res = parser.parse(transaction)
        self.assertEqual(res.contractType, contract)
        self.assertEqual(res.method.fn_name, "testMethod1")
        self.assertEqual(len(res.args.keys()), 1)
        self.assertEqual(res.args["_arg1"], 6)

    def test_multiple_args(self):
        """Test parsing a transaction for contract methods with several arguments"""
        contract = make_contract_multple_args(
            ["uint256", "address", "address", "uint256"]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build valid raw transaction
        payload = method_signature(contract.functions.testMethod1)
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
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )

        res = parser.parse(transaction)
        self.assertEqual(res.contractType, contract)
        self.assertEqual(res.method.fn_name, "testMethod1")
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
        payload = method_signature(contract.functions.testMethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        transaction = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertRaises(InsufficientDataBytes, parser.parse, transaction)

    def test_invalid_contract(self):
        """Test parsing a transaction for an unrecognized contract"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build invalid raw transaction, no contract at address 0x2222...
        payload = method_signature(contract.functions.testMethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )
        transaction = InputTransaction(
            HexBytes("0x2222222222222222222222222222222222222222"), HexBytes(payload)
        )

        self.assertRaises(ValueError, parser.parse, transaction)

    def test_invalid_method_name(self):
        """Test that the parser fails when given a method name which doesn't exist"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        transaction = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes(
                "0x343434340000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        self.assertRaises(ValueError, parser.parse, transaction)

    def test_no_method_args(self):
        """Test that the parser fails when no arguments are specified"""
        contract = make_basic_contract()
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        payload = method_signature(contract.functions.testMethod1)
        transaction = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), payload
        )
        self.assertRaises(InsufficientDataBytes, parser.parse, transaction)


class TestVerify(TestCase):
    def test_arg(self):
        """Test basic functionality of AllowedArg"""
        allowed_arg = AllowedArg([1, 2], [])

        # valid value
        self.assertTrue(allowed_arg.verify(1))

        self.assertFalse(allowed_arg.verify(10))

    def test_arg_group(self):
        """Test grouping functionality of AllowedArg (normally used for groups of users)"""
        allowed_arg = AllowedArg([10], [ArgumentGroup([1, 2])])

        # valid, 1 is in a valid group
        self.assertTrue(allowed_arg.verify(1))

        # valid, 10 is an allowed value
        self.assertTrue(allowed_arg.verify(10))

        # invalid, -1 is not allowed by either the individual args, nor groups
        self.assertFalse(allowed_arg.verify(-1))

    def test_role_one_arg(self):
        """Test basic functionality of ALlowedRole"""
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})

        # valid, _arg1=1 is allowed
        self.assertTrue(allowed_role.verify_arg("_arg1", 1))

        # invalid, _arg1=10 is not allowed
        self.assertFalse(allowed_role.verify_arg("_arg1", 10))

    def test_role_multiple_args(self):
        """Test that AllowedRole works as intended with multiple roles in the picture"""
        allowed_arg1 = AllowedArg([1, 2], [])
        allowed_arg2 = AllowedArg([10], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg1, "_arg2": allowed_arg2})

        # valid, _arg1=1 is allowed
        self.assertTrue(allowed_role.verify_arg("_arg1", 1))

        # valid, _arg2=10 is allowed
        self.assertTrue(allowed_role.verify_arg("_arg2", 10))

        # invalid, _arg1=10 is not allowed
        self.assertFalse(allowed_role.verify_arg("_arg1", 10))

        # invalid, _arg2=1 not allowed
        self.assertFalse(allowed_role.verify_arg("_arg2", 1))

    def test_role_missing_arg(self):
        """
        Test what happens if user provides a valid arg which isn't present in config.
        Current behavior is that the arg will be treated as optional
        """
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})

        # valid, _arg2 not specified, so allowed by default
        self.assertTrue(allowed_role.verify_arg("_arg2", 1))

    def test_method(self):
        """Test basic functionality of AllowedMethod"""
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})
        allowed_method = AllowedMethod({"testRole": allowed_role})

        contract = make_basic_contract()

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertTrue(allowed_method.verify(request))

        # failing transaction, no valid role
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    def test_method_multiple_args(self):
        """Test AllowedMethod with a contract method that takes multiple arguments"""
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg, "_arg2": allowed_arg})
        allowed_method = AllowedMethod({"testRole1": allowed_role})

        contract = make_contract_multple_args(["uint256", "uint256"])

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {"_arg1": 1, "_arg2": 1},
        )
        request = TransactionRequest(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, _arg2=10 not allowed for testRole1
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {"_arg1": 1, "_arg2": 10},
        )
        request = TransactionRequest(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    def test_method_multiple_roles(self):
        """Test various combinations of roles with slightly different permissions on the same method"""
        allowed_arg1 = AllowedArg([1, 2], [])
        allowed_arg2 = AllowedArg([10], [])
        allowed_role1 = AllowedRole({"_arg1": allowed_arg1, "_arg1": allowed_arg1})
        allowed_role2 = AllowedRole({"_arg2": allowed_arg2, "_arg2": allowed_arg2})
        allowed_method = AllowedMethod(
            {"testRole1": allowed_role1, "testRole2": allowed_role2}
        )

        contract = make_contract_multple_args(["uint256", "uint256"])

        # valid transaction, one good role
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
                "_arg2": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # valid transaction, one bad role and one good one
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 10,
                "_arg2": 10,
            },
        )
        request = TransactionRequest(transaction, ["testRole1", "testRole2"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, two bad roles
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": -1,
                "_arg2": 10,
            },
        )
        request = TransactionRequest(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

        # valid transaction, _arg1=1 allowed by testRole1, and _arg1=10 allowed by testRole2
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
                "_arg2": 10,
            },
        )
        request = TransactionRequest(transaction, ["testRole1", "testRole2"])
        self.assertTrue(allowed_method.verify(request))

    def test_contract(self):
        """Test basic functionality of AllowedContract"""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])

        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})
        allowed_method = AllowedMethod({"testRole": allowed_role})
        allowed_contract = AllowedContract(contract, {"testMethod1": allowed_method})

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertTrue(allowed_contract.verify(request))

        # failing transaction, no valid methods
        transaction = ParsedTransaction(
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod2,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertRaises(UnrecognizedRequestError, allowed_contract.verify, request)

    def test_verifier(self):
        """Test basic functionality of Verifier"""
        contract = make_basic_contract()
        contract2 = make_basic_contract()
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})
        allowed_method = AllowedMethod({"testRole": allowed_role})
        allowed_contract = AllowedContract(contract, {"testMethod1": allowed_method})
        verifier = Verifier([allowed_contract])

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertTrue(verifier.verify(request))

        # failing transaction, wrong contract type
        transaction = ParsedTransaction(
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract2,
            contract2.functions.testMethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertRaises(UnrecognizedRequestError, verifier.verify, request)

    def test_permission_from_dict(self):
        """Test that user can load a Verifier object from a dictionary, and that it works as expected."""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])
        contracts = {"testContract": contract}
        data = {
            "testContract": {
                "testMethod1": {"testRole": {"_arg1": [1, 2]}},
                "testMethod2": {"testRole": {"_arg1": [10]}},
            }
        }
        permissions = permissions_from_dict(data, contracts)

        # valid transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertTrue(permissions.verify(request))

        # valid transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod2,
            {
                "_arg1": 10,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertTrue(permissions.verify(request))

        # invalid transaction, arg not allowed for testRole
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod2,
            {
                "_arg1": -1,
            },
        )
        request = TransactionRequest(transaction, ["testRole"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)

        # invalid transaction, no perms for testRole2
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod2,
            {
                "_arg1": 1,
            },
        )
        request = TransactionRequest(transaction, ["testRole2"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)


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

        # good transaction, testmethod1(_arg1=100) allowed for testRole1
        self.assertTrue(
            policy_engine.verify(
                contract_address,
                "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064",
                ["testRole1"],
            ),
        )

        # bad transaction, testmethod1(_arg1=1) not allowed for testRole1
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            contract_address,
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000001",
            ["testRole1"],
        )

        # bad transaction, testRole2 not allowed to use testmethod1
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            contract_address,
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064",
            ["testRole2"],
        )

        # good transaction, testRole2 not allowed to use testmethod1, but testRole1 is
        self.assertTrue(
            policy_engine.verify(
                contract_address,
                "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064",
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

        # testmethod2 requires a uint256 and an address

        # valid transaction, _arg1=100, arg2=0x1212... is allowed for testRole1
        payload = (
            "0x9bfff434"
            + "0000000000000000000000000000000000000000000000000000000000000064"
            + "0000000000000000000000001212121212121212121212121212121212121212"
            + "0000000000000000000000001212121212121212121212121212121212121212"
        )
        self.assertTrue(policy_engine.verify(contract_address, payload, ["testRole1"]))

        # valid transaction, _arg1=100,arg2=3434... is allowed for testRole1
        payload = (
            "0x9bfff434"
            + "0000000000000000000000000000000000000000000000000000000000000064"
            + "0000000000000000000000003434343434343434343434343434343434343434"
        )
        self.assertTrue(policy_engine.verify(contract_address, payload, ["testRole1"]))

        # invalid transaction, _arg2 not allowed for testRole1 when _arg1 = 200
        payload = (
            "0x9bfff434"
            + "00000000000000000000000000000000000000000000000000000000000000C8"
            + "0000000000000000000000007878787878787878787878787878787878787878"
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
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
        self.assertTrue(policy_engine.verify(contract_address, payload, ["testRole2"]))


def make_basic_contract() -> Type[Contract]:
    """Construct a basic web3 contract with one method (taking a uint256 as input)"""
    return w3.eth.contract(
        abi=[
            {
                "constant": False,
                "inputs": [
                    {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                ],
                "name": "testMethod1",
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
                "name": "testMethod1",
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
                "name": f"testMethod{method_num+1}",
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
