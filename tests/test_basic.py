from unittest import TestCase
from hexbytes import HexBytes
from web3.auto import w3
from eth_abi.exceptions import InsufficientDataBytes

from web3_policy_engine.contract_common import (
    InputTransaction,
    ParsedTransaction,
    contract_from_json,
    method_signature,
    Request,
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
        contract = contract_from_json("data/local_data/abi/test_abi.json")
        self.assertEqual("testmethod1", contract.functions.testmethod1.fn_name)


class TestParser(TestCase):
    def test_basic(self):
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "multiply",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes(
                    "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
                ),
            )
        )
        self.assertEqual(res.contractType, contract)
        self.assertEqual(res.method.fn_name, "multiply")
        self.assertEqual(len(res.args.keys()), 1)
        self.assertEqual(res.args["_arg1"], 6)

    def test_multiple_method_args(self):
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
                        {"internalType": "address", "name": "_arg2", "type": "address"},
                        {"internalType": "address", "name": "_arg3", "type": "address"},
                        {"internalType": "uint256", "name": "_arg4", "type": "uint256"},
                    ],
                    "name": "multiply",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )
        payload = method_signature(contract.functions.multiply)
        self.assertEqual(payload, HexBytes("0x9dc807f9"))
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

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes(payload),
            )
        )
        self.assertEqual(res.contractType, contract)

        self.assertEqual(res.method.fn_name, "multiply")
        self.assertEqual(len(res.args.keys()), 4)
        self.assertEqual(res.args["_arg1"], 1)
        self.assertEqual(
            res.args["_arg2"], "0x2222222222222222222222222222222222222222"
        )
        self.assertEqual(
            res.args["_arg3"], "0x3333333333333333333333333333333333333333"
        )
        self.assertEqual(res.args["_arg4"], 4)

    def test_invalid_contract(self):
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "multiply",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        transaction = InputTransaction(
            HexBytes("0x2222222222222222222222222222222222222222"),
            HexBytes(
                "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        self.assertRaises(ValueError, parser.parse, transaction)

    def test_invalid_method_name(self):
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "multiply",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
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
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "multiply",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        transaction = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0xc6888fa1"),
        )
        self.assertRaises(InsufficientDataBytes, parser.parse, transaction)


class TestVerify(TestCase):
    def test_arg(self):
        allowed_arg = AllowedArg([1, 2], [])

        # valid value
        self.assertTrue(allowed_arg.verify(1))

        self.assertFalse(allowed_arg.verify(10))

    def test_arg_group(self):
        allowed_arg = AllowedArg([10], [ArgumentGroup([1, 2])])

        # valid, 1 is in a valid group
        self.assertTrue(allowed_arg.verify(1))

        # valid, 10 is an allowed value
        self.assertTrue(allowed_arg.verify(10))

        # invalid, -1 is not allowed by either the individual args, nor groups
        self.assertFalse(allowed_arg.verify(-1))

    def test_role_one_arg(self):
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})

        # valid, _arg1=1 is allowed
        self.assertTrue(allowed_role.verify_arg("_arg1", 1))

        # invalid, _arg1=10 is not allowed
        self.assertFalse(allowed_role.verify_arg("_arg1", 10))

    def test_role_multiple_args(self):
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
        Test what happens if user provides a valid arg which isn't present in config
        current behavior is that the arg will be treated as optional
        """
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})

        # valid, _arg2 not specified, so allowed by default
        self.assertTrue(allowed_role.verify_arg("_arg2", 1))

    def test_method(self):
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role = AllowedRole({"_arg1": allowed_arg})
        allowed_method = AllowedMethod({"testRole": allowed_role})

        contract = w3.eth.contract(
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
                },
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "testMethod2",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                },
            ]
        )

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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    def test_method_multiple_args(self):
        allowed_arg = AllowedArg([1, 2], [])
        allowed_role1 = AllowedRole({"_arg1": allowed_arg, "_arg2": allowed_arg})
        allowed_role2 = AllowedRole({"_arg1": allowed_arg})
        allowed_method = AllowedMethod(
            {"testRole1": allowed_role1, "testRole2": allowed_role2}
        )

        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
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

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {"_arg1": 1, "_arg2": 1},
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, _arg2=10 not allowed for
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod1,
            {"_arg1": 1, "_arg2": 10},
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify,request)

    def test_multiple_roles(self):
        allowed_arg1 = AllowedArg([1, 2], [])
        allowed_arg2 = AllowedArg([10], [])
        allowed_role1 = AllowedRole({"_arg1": allowed_arg1, "_arg2": allowed_arg1})
        allowed_role2 = AllowedRole({"_arg1": allowed_arg2, "_arg2": allowed_arg2})
        allowed_method = AllowedMethod(
            {"testRole1": allowed_role1, "testRole2": allowed_role2}
        )

        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
                        {"internalType": "uint256", "name": "_arg2", "type": "uint256"},
                    ],
                    "name": "testMethod",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                },
            ]
        )

        # valid transaction, one good role
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": 1,
                "_arg2": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # valid transaction, one bad role and one good one
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": 10,
                "_arg2": 10,
            },
        )
        request = Request(transaction, ["testRole1", "testRole2"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, two bad roles
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": -1,
                "_arg2": 10,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

        # valid transaction, _arg1=1 allowed by testRole1, and _arg1=10 allowed by testRole2

    def test_contract(self):
        contract = w3.eth.contract(
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
                },
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "testMethod2",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                },
            ]
        )

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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole"])
        self.assertRaises(UnrecognizedRequestError, allowed_contract.verify, request)

    def test_verifier(self):
        contract = w3.eth.contract(
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
                },
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "testMethod2",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                },
            ]
        )
        contract2 = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [],
                    "name": "testMethod1",
                    "outputs": [],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                }
            ]
        )
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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole"])
        self.assertRaises(UnrecognizedRequestError, verifier.verify, request)

    def test_permission_from_dict(self):
        contract = w3.eth.contract(
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
                },
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
                    ],
                    "name": "testMethod2",
                    "outputs": [
                        {"internalType": "uint256", "name": "_out", "type": "uint256"}
                    ],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function",
                },
            ]
        )
        contracts = {"testContract": contract}
        data = {
            "testContract": {
                "testMethod1": [{"testRole": {"_arg1": [1, 2]}}],
                "testMethod2": [{"testRole": {"_arg1": [10]}}],
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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole"])
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
        request = Request(transaction, ["testRole2"])
        self.assertRaises(InvalidPermissionsError, permissions.verify, request)


class TestPolicyEngine(TestCase):
    def test_from_file_basic(self):
        # set up policy engine
        policy_engine = PolicyEngine(
            "data/local_data/test_contract_addresses.json",
            "data/local_data/test_config.yml",
            "data/local_data/test_groups.yml",
        )

        # testmethod1 requires a uint256

        # good transaction, _arg1=100 allowed for testRole1
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["testRole1"]))

        # bad transaction, _arg1=1 not allowed for testRole1
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000001"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            input_transaction1,
            ["testRole1"],
        )

        # bad transaction, user not allowed to use testmethod1
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            input_transaction1,
            ["testRole2"],
        )

        # good transaction, user not allowed to use testmethod1, but testRole1 is
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(
            policy_engine.verify(input_transaction1, ["testRole2", "testRole1"])
        )

    def test_from_file_groups(self):
        # set up policy engine
        policy_engine = PolicyEngine(
            "data/local_data/test_contract_addresses.json",
            "data/local_data/test_config.yml",
            "data/local_data/test_groups.yml",
        )

        # testmethod2 requires a uint256 and an address

        # valid transaction, _arg1=100, arg2=0x1212... is allowed for testRole1
        payload = (
            HexBytes("0x9bfff434")
            + HexBytes(
                "0000000000000000000000000000000000000000000000000000000000000064"
            )
            + HexBytes(
                "0000000000000000000000001212121212121212121212121212121212121212"
                "0000000000000000000000001212121212121212121212121212121212121212"
            )
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["testRole1"]))

        # valid transaction, _arg1=100,arg2=3434... is allowed for testRole1
        payload = (
            HexBytes("0x9bfff434")
            + HexBytes(
                "0000000000000000000000000000000000000000000000000000000000000064"
            )
            + HexBytes(
                "0000000000000000000000003434343434343434343434343434343434343434"
            )
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["testRole1"]))

        # invalid transaction, _arg2 not allowed for testRole1 when _arg1 = 200
        payload = (
            HexBytes("0x9bfff434")
            + HexBytes(
                "00000000000000000000000000000000000000000000000000000000000000C8"
            )
            + HexBytes(
                "0000000000000000000000007878787878787878787878787878787878787878"
            )
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertRaises(
            InvalidPermissionsError,
            policy_engine.verify,
            input_transaction1,
            ["testRole1"],
        )

        # valid transaction, _arg2 is allowed when _arg1=100 for role testRole2
        payload = (
            HexBytes("0x9bfff434")
            + HexBytes(
                "0000000000000000000000000000000000000000000000000000000000000064"
            )
            + HexBytes(
                "0000000000000000000000007878787878787878787878787878787878787878"
            )
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["testRole2"]))
