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
        allowed_arg = AllowedArg("_arg1", [1, 2], [])
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

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_arg.verify(request))

        # invalid value
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertFalse(allowed_arg.verify(request))

        # missing value
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg2": 1,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertFalse(allowed_arg.verify(request))

    def test_arg_group(self):
        allowed_arg = AllowedArg("_arg1", [10], [ArgumentGroup([1, 2])])
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

        # valid transaction, 1 is in the specified group
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_arg.verify(request))

        # valid transaction, 10 is an allowed value
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_arg.verify(request))

        # invalid transaction, -1 is not allowed by either the individual args, nor groups
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {"_arg1": -1},
        )
        request = Request(transaction, ["testRole"])
        self.assertFalse(allowed_arg.verify(request))

    def test_role_one_arg(self):
        allowed_arg = AllowedArg("_arg1", [1, 2], [])
        allowed_role = AllowedRole("testRole", [allowed_arg])
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
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

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 1,
            },
        )

        # valid role
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_role.verify(request))

        # invalid role
        request = Request(transaction, ["testRole2"])
        self.assertFalse(allowed_role.verify(request))

        # one valid and one invalid role
        request = Request(transaction, ["testRole2", "testRole"])
        self.assertTrue(allowed_role.verify(request))

    def test_role_multiple_args(self):
        allowed_arg1 = AllowedArg("_arg1", [1, 2], [])
        allowed_arg2 = AllowedArg("_arg2", [10], [])
        allowed_role = AllowedRole("testRole", [allowed_arg1, allowed_arg2])
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
                        {"internalType": "uint256", "name": "_arg2", "type": "uint256"},
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

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {"_arg1": 1, "_arg2": 10},
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_role.verify(request))

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {"_arg1": 2, "_arg2": 10},
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_role.verify(request))

        # failing transaction (one arg right, other wrong)
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {"_arg1": 1, "_arg2": -1},
        )
        request = Request(transaction, ["testRole"])
        self.assertFalse(allowed_role.verify(request))

    def test_role_missing_arg(self):
        """
        Test what happens if user provides a valid arg which isn't present in config
        current behavior is that the arg will be treated as optional
        """
        allowed_arg = AllowedArg("_arg1", [1, 2], [])
        allowed_role = AllowedRole("testRole", [allowed_arg])
        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"},
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

        # working transaction
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.multiply,
            {
                "_arg1": 1,
                "_arg2": 10,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertTrue(allowed_role.verify(request))

    def test_method(self):
        allowed_arg = AllowedArg("_arg1", [1, 2], [])
        allowed_role = AllowedRole("testRole", [allowed_arg])
        allowed_method = AllowedMethod("testMethod1", [allowed_role])

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

        # failing transaction, method not allowed
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod2,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertRaises(UnrecognizedRequestError, allowed_method.verify, request)

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

    def test_multiple_roles(self):
        allowed_arg1 = AllowedArg("_arg1", [1, 2], [])
        allowed_role1 = AllowedRole("testRole1", [allowed_arg1])
        allowed_arg2 = AllowedArg("_arg1", [10], [])
        allowed_role2 = AllowedRole("testRole2", [allowed_arg2])
        allowed_method = AllowedMethod("testMethod", [allowed_role1, allowed_role2])

        contract = w3.eth.contract(
            abi=[
                {
                    "constant": False,
                    "inputs": [
                        {"internalType": "uint256", "name": "_arg1", "type": "uint256"}
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

        # working transaction, one good role
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # working transaction, one bad role and one good one
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": 10,
            },
        )
        request = Request(transaction, ["testRole1", "testRole2"])
        self.assertTrue(allowed_method.verify(request))

        # failing transaction, two bad roles
        transaction = ParsedTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testMethod,
            {
                "_arg1": -1,
            },
        )
        request = Request(transaction, ["testRole"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

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

        allowed_arg = AllowedArg("_arg1", [1, 2], [])
        allowed_role = AllowedRole("testRole", [allowed_arg])
        allowed_method = AllowedMethod("testMethod1", [allowed_role])
        allowed_contract = AllowedContract(contract, [allowed_method])

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
        self.assertRaises(UnrecognizedRequestError, allowed_contract.verify, request)

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

    def test_permission_from_dict(self):
        contracts = {"testContract": w3.eth.contract(abi=[])}
        data = {
            "testContract": {
                "safeTransferFrom": [
                    {
                        "manager": {
                            "_to": [
                                "0x1212121212121212121212121212121212121212",
                                "0x3434343434343434343434343434343434343434",
                            ],
                            "_value": [100],
                        }
                    },
                    {
                        "manager": {
                            "_to": ["0x3434343434343434343434343434343434343434"],
                            "_value": [200],
                        }
                    },
                ]
            }
        }
        permissions = permissions_from_dict(data, contracts)
        self.assertEqual(len(permissions.allowed_contracts), 1)

        allowed_contract = permissions.allowed_contracts[0]
        self.assertEqual(allowed_contract.contract_type, contracts["testContract"])
        self.assertEqual(len(allowed_contract.allowed_methods), 1)

        allowed_method = allowed_contract.allowed_methods[0]
        self.assertEqual(allowed_method.name, "safeTransferFrom")
        self.assertEqual(len(allowed_method.allowed_roles), 2)

        allowed_role1 = allowed_method.allowed_roles[0]
        allowed_role2 = allowed_method.allowed_roles[1]
        self.assertEqual(allowed_role1.name, "manager")
        self.assertEqual(allowed_role2.name, "manager")

        role1_to = allowed_role1.allowed_args[0]
        self.assertEqual(role1_to.name, "_to")
        self.assertEqual(
            role1_to.options,
            data["testContract"]["safeTransferFrom"][0]["manager"]["_to"],
        )
        role1_value = allowed_role1.allowed_args[1]
        self.assertEqual(role1_value.name, "_value")
        self.assertEqual(
            role1_value.options,
            data["testContract"]["safeTransferFrom"][0]["manager"]["_value"],
        )

        role2_to = allowed_role2.allowed_args[0]
        self.assertEqual(role2_to.name, "_to")
        self.assertEqual(
            role2_to.options,
            data["testContract"]["safeTransferFrom"][1]["manager"]["_to"],
        )
        role2_value = allowed_role2.allowed_args[1]
        self.assertEqual(role2_value.name, "_value")
        self.assertEqual(
            role2_value.options,
            data["testContract"]["safeTransferFrom"][1]["manager"]["_value"],
        )


class TestPolicyEngine(TestCase):
    def test_from_file_basic(self):
        # set up policy engine
        policy_engine = PolicyEngine(
            "data/local_data/test_contract_addresses.json",
            "data/local_data/test_config.yml",
            "data/local_data/test_groups.yml",
        )

        # testmethod1 requires a uint256

        # good transaction, _arg1=100 allowed for manager
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["manager"]))

        # bad transaction, _arg1=1 not allowed for manager
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
            ["manager"],
        )

        # bad transaction, user not allowed to use testmethod1
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertRaises(
            InvalidPermissionsError, policy_engine.verify, input_transaction1, ["user"]
        )

        # good transaction, user not allowed to use testmethod1, but manager is
        payload = HexBytes(
            "0x6ba4caa90000000000000000000000000000000000000000000000000000000000000064"
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["user", "manager"]))

    def test_from_file_groups(self):
        # set up policy engine
        policy_engine = PolicyEngine(
            "data/local_data/test_contract_addresses.json",
            "data/local_data/test_config.yml",
            "data/local_data/test_groups.yml",
        )

        # testmethod2 requires a uint256 and an address

        # valid transaction
        payload = (
            HexBytes("0x9bfff434")
            + HexBytes(
                "0000000000000000000000000000000000000000000000000000000000000064"
            )
            + HexBytes(
                "0000000000000000000000001212121212121212121212121212121212121212"
            )
        )
        input_transaction1 = InputTransaction(
            HexBytes("0x1234123412341234123412341234123412341234"), HexBytes(payload)
        )
        self.assertTrue(policy_engine.verify(input_transaction1, ["manager"]))

        # valid transaction
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
        self.assertTrue(policy_engine.verify(input_transaction1, ["manager"]))

        # bad transaction, _arg2 not allowed for manager when _arg1 = 200
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
            ["manager"],
        )

        # valid transaction, _arg2 is allowed when _arg1=100
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
        self.assertTrue(policy_engine.verify(input_transaction1, ["manager"]))