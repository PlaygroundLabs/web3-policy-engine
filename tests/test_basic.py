from unittest import TestCase
from hexbytes import HexBytes

from web3_policy_engine.schemas import ABI_from_json, ABI, ABI_Method, InputTransaction
from web3_policy_engine.parse_transaction import Parser


class TestABI(TestCase):
    def test_from_json(self):
        abi_json = ABI_from_json("testABI", "data/local_data/abi/test_abi.json")
        self.assertEqual(abi_json.name, "testABI")
        self.assertTrue("testmethod1" in abi_json.method_names.keys())
        self.assertEqual(abi_json.method_names["testmethod1"].input_names, ["_arg1"])
        self.assertEqual(abi_json.method_names["testmethod1"].input_types, ["uint256"])


class TestParser(TestCase):
    def test_basic(self):
        method1 = ABI_Method("multiply", [{"type": "uint256", "name": "_num"}])
        contract1 = ABI("testcontract", [method1])
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract1}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes(
                    "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
                ),
            )
        )
        self.assertNotEqual(res, None)
        self.assertEqual(res.contractType, contract1)
        self.assertEqual(res.method, method1)
        self.assertEqual(len(res.args), 1)
        self.assertEqual(res.args[0], 6)

    def test_multiple_method_args(self):
        method1 = ABI_Method(
            "multiply",
            [
                {"type": "uint256", "name": "_num1"},
                {"type": "address", "name": "_address"},
                {"type": "address", "name": "_address2"},
                {"type": "uint256", "name": "_num2"},
            ],
        )
        self.assertEqual(method1.hash(), HexBytes("0x9dc807f9"))
        contract1 = ABI("testcontract", [method1])
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract1}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes("0x9dc807f90000000000000000000000000000000000000000000000000000000000000001222222222222222222222222222222222222222233333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000004"),
            )
        )
        self.assertNotEqual(res, None)
        self.assertEqual(res.contractType, contract1)
        self.assertEqual(res.method, method1)
        self.assertEqual(len(res.args), 4)
        self.assertEqual(res.args[0], 1)
        self.assertEqual(res.args[1], HexBytes("0x2222222222222222222222222222222222222222"))
        self.assertEqual(res.args[2], HexBytes("0x3333333333333333333333333333333333333333"))
        self.assertEqual(res.args[3], 4)

    def test_invalid_contract(self):
        method1 = ABI_Method("multiply", [{"type": "uint256", "name": "_num"}])
        contract1 = ABI("testcontract", [method1])
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract1}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x2222222222222222222222222222222222222222"),
                HexBytes(
                    "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
                ),
            )
        )
        self.assertEqual(res, None)

    def test_invalid_method_name(self):
        method1 = ABI_Method("multiply", [{"type": "uint256", "name": "_num"}])
        contract1 = ABI("testcontract", [method1])
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract1}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes(
                    "0x343434340000000000000000000000000000000000000000000000000000000000000006"
                ),
            )
        )
        self.assertEqual(res, None)

    def test_no_method_args(self):
        method1 = ABI_Method("multiply", [{"type": "uint256", "name": "_num"}])
        contract1 = ABI("testcontract", [method1])
        parser = Parser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract1}
        )

        res = parser.parse(
            InputTransaction(
                HexBytes("0x1234123412341234123412341234123412341234"),
                HexBytes("0xc6888fa1"),
            )
        )
        self.assertNotEqual(res, None)
        self.assertEqual(res.contractType, contract1)
        self.assertEqual(res.method, method1)
        self.assertEqual(len(res.args), 1)
        self.assertEqual(res.args[0], 0)
