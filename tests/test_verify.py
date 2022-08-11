from unittest import TestCase
from hexbytes import HexBytes
from web3_policy_engine.contract_common import (
    InvalidPermissionsError,
    ParsedJsonRpc,
    ParsedMessage,
    ParsedTransaction,
    Request,
    UnrecognizedRequestError,
)

from web3_policy_engine.verify_permissions import (
    AllowedEthContractMethod,
    AllowedValue,
    AllowedGroup,
    ArgumentGroup,
    AllowedContract,
    AllowedEthMessageMethod,
    AllowedContractMethod,
    Verifier,
)

from .utils_for_tests import (
    make_basic_contract,
    make_contract_multiple_methods,
    make_contract_multple_args,
)


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
        self.assertTrue(allowed_method.verify(request))

        # failing transaction, no valid role
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
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {"_arg1": 1, "_arg2": 1},
        )
        request = Request(transaction, ["testRole1"])
        self.assertTrue(allowed_method.verify(request))

        # invalid transaction, _arg2=10 not allowed for testRole1
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {"_arg1": 1, "_arg2": 10},
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_method.verify, request)

    def test_contract(self):
        """Test basic functionality of AllowedContract"""
        contract = make_contract_multiple_methods([["uint256"], ["uint256"]])

        allowed_arg = AllowedValue(1, ["testRole1"])
        allowed_method = AllowedContractMethod({"_arg1": [allowed_arg]})
        allowed_contract = AllowedContract(contract, {"testmethod1": allowed_method})

        # working transaction
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
        self.assertTrue(allowed_contract.verify(request))

        # failing transaction, no valid methods
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod2,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
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
        self.assertTrue(allowed_eth_method.verify(request))

        # failing transaction, wrong contract type
        transaction = ParsedTransaction(
            "eth_sendTransaction",
            HexBytes("0x5678567856785678567856785678567856785678"),
            HexBytes("0x0"),
            contract2,
            contract2.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_eth_method.verify, request)

        # failing transaction, wrong request type
        message = ParsedMessage("eth_sign", "testmessage")
        request = Request(message, ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, allowed_eth_method.verify, request)

    def test_allowed_eth_message_method(self):
        """Test AllowedEthMessageMethod"""
        allowed_arg1 = AllowedValue("message1", ["testRole1"])
        allowed_message = AllowedEthMessageMethod([allowed_arg1])

        # valid request, testRole1 does have permission to sign "message1"
        message = ParsedMessage("eth_sign", "message1")
        request = Request(message, ["testRole1"])
        self.assertTrue(allowed_message.verify(request))

        # invalid request, testRole1 does not have permission to sign "submessage1"
        message = ParsedMessage("eth_sign", "submessage1")
        request = Request(message, ["testRole1"])
        self.assertRaises(InvalidPermissionsError, allowed_message.verify, request)

        request = ParsedJsonRpc("eth_sign")
        request = Request(request, ["testRole1"])
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
        self.assertTrue(verifier.verify(request))

        # invalid request, incorrect eth method
        transaction = ParsedTransaction(
            "eth_sign",
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x0"),
            contract,
            contract.functions.testmethod1,
            {
                "_arg1": 1,
            },
        )
        request = Request(transaction, ["testRole1"])
        self.assertRaises(UnrecognizedRequestError, verifier.verify, request)
