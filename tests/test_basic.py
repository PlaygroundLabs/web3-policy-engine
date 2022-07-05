from unittest import TestCase
from hexbytes import HexBytes
from web3.auto import w3
from eth_abi.exceptions import InsufficientDataBytes 

from web3_policy_engine.contract_common import (
    InputTransaction,
    contract_from_json,
    method_signature,
)
from web3_policy_engine.parse_transaction import Parser


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
