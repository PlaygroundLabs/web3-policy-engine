from unittest import TestCase
from hexbytes import HexBytes

from web3_policy_engine.schemas import Transaction
from web3_policy_engine.parse_transaction import Parser


class TestWeb3(TestCase):
    def test_parser(self):
        parser = Parser(["multiply(uint256)"])
        transaction = Transaction(
            HexBytes("0x6ff93b4b46b41c0c3c9baee01c255d3b4675963d"),
            HexBytes("0xc6888fa10000000000000000000000000000000000000000000000000000000000000006"),
        )
        self.assertTrue(parser.is_valid_method(transaction))
