from unittest import TestCase
from hexbytes import HexBytes
from yaml import safe_load

from web3_policy_engine.schemas import Transaction
from web3_policy_engine.parse_transaction import Parser


class TestParser(TestCase):
    def test_address(self):
        parser = Parser(
            {
                HexBytes("0x1234123412341234123412341234123412341234"): {
                    "multiply(uint256)": ["role1"]
                }
            }
        )
        transaction = Transaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes(
                "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        self.assertTrue(parser.is_valid_address(transaction))

        transaction = Transaction(
            HexBytes("0x8888888888888888888888888888888888888888"),
            HexBytes("0x0"),
        )
        self.assertFalse(parser.is_valid_address(transaction))

    def test_method(self):
        parser = Parser(
            {
                HexBytes("0x1234123412341234123412341234123412341234"): {
                    "multiply(uint256)": ["role1"]
                }
            }
        )
        transaction = Transaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes(
                "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        self.assertTrue(parser.is_valid_method(transaction))

        transaction = Transaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes("0x909090909"),
        )
        self.assertFalse(parser.is_valid_method(transaction))

        transaction = Transaction(
            HexBytes("0x9999999999999999999999999999999999999999"),
            HexBytes(
                "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        # self.assertRaises(ValueError, parser.is_valid_method, transaction)
        self.assertFalse(parser.is_valid_method(transaction))
    
    def test_role(self):
        parser = Parser(
            {
                HexBytes("0x1234123412341234123412341234123412341234"): {
                    "multiply(uint256)": ["role1"]
                }
            }
        )
        transaction = Transaction(
            HexBytes("0x1234123412341234123412341234123412341234"),
            HexBytes(
                "0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"
            ),
        )
        self.assertTrue(parser.is_valid_role(transaction, ["role1"]))
        self.assertFalse(parser.is_valid_role(transaction, ["role2"]))
        self.assertTrue(parser.is_valid_role(transaction, ["role2", "role1"]))
        self.assertFalse(parser.is_valid_role(transaction, []))


    def test_load_from_yaml(self):
        with open("data/local_data/test_config.yml", "r") as file_handle:
            yaml_data = safe_load(file_handle)
            # convert from str to HexBytes
            yaml_data = {HexBytes(key):value for key,value in yaml_data.items()}
            parser = Parser(yaml_data)
            transaction = Transaction(
                HexBytes("0x2222222222222222222222222222222222222222"),
                HexBytes("0xc6888fa1"),
            )
            self.assertTrue(parser.is_valid_address(transaction))
