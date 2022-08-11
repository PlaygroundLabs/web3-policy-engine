from hexbytes import HexBytes
from unittest import TestCase

from web3_policy_engine.contract_common import InputJsonRpc, ParseError
from web3_policy_engine.parse_transaction import (
    Parser,
    MessageParser,
    TransactionParser,
    parse,
)
from web3_policy_engine.loader import method_signature

from .utils_for_tests import make_basic_contract, make_contract_multple_args


class TestParser(TestCase):
    def test_raw_json_bad_jsonrpc(self):
        """Make sure that an error is raised if a transaction is built from a bad json rpc"""
        parser = Parser({})
        self.assertRaises(ParseError, parser.raw_json_rpc_to_input, {})
        self.assertRaises(ParseError, parser.raw_json_rpc_to_input, {"params": []})
        self.assertRaises(
            ParseError, parser.raw_json_rpc_to_input, {"params": [{"to": "0x0"}]}
        )
        self.assertRaises(
            ParseError,
            parser.raw_json_rpc_to_input,
            {"eth_method": "eth_signTransaction"},
        )

    def test_parse_bad_eth_method(self):
        """Make sure that an error is raised if a transaction is built from a bad json rpc"""
        parser = Parser({})
        self.assertRaises(
            ParseError,
            parser.parse,
            {"method": "eth_signTransaction", "params": [{"to": "0x0"}]},
        )

    def test_parse_basic(self):
        contract = make_basic_contract()
        contract_address = HexBytes("0x1234123412341234123412341234123412341234")
        tx_parser = TransactionParser({contract_address: contract})
        parser = Parser({"eth_sendTransaction": tx_parser})
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )

        json_rpc = {
            "method": "eth_sendTransaction",
            "params": [
                {
                    "data": payload,
                    "to": contract_address.hex(),
                }
            ],
        }
        res = parser.parse(json_rpc)

        self.assertEqual(res.contract_type, contract)  # type: ignore
        self.assertEqual(res.contract_method.fn_name, "testmethod1")  # type: ignore
        self.assertEqual(len(res.contract_method_args.keys()), 1)  # type: ignore
        self.assertEqual(res.contract_method_args["_arg1"], 6)  # type: ignore

    def test_parse_function_basic(self):
        contract = make_basic_contract()
        contract_address = "0x1234123412341234123412341234123412341234"
        contract_addresses = {contract_address: contract}

        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )

        json_rpc = {
            "method": "eth_sendTransaction",
            "params": [
                {
                    "data": payload,
                    "to": contract_address,
                }
            ],
        }
        res = parse(json_rpc, contracts=contract_addresses)

        self.assertEqual(res.contract_type, contract)  # type: ignore
        self.assertEqual(res.contract_method.fn_name, "testmethod1")  # type: ignore
        self.assertEqual(len(res.contract_method_args.keys()), 1)  # type: ignore
        self.assertEqual(res.contract_method_args["_arg1"], 6)  # type: ignore


class TestTransactionParser(TestCase):
    def build_input_json_rpc(
        self, data: str, to: str = "0x1234123412341234123412341234123412341234"
    ) -> InputJsonRpc:
        _from = "0x573dd41c9e904f908d14f7150438bc7dc210baa9"
        gas_price = "0x70657586c"
        json_rpc = InputJsonRpc(
            method="eth_sendTransaction",
            params=[
                {
                    "from": _from,
                    "data": data,
                    "gasPrice": gas_price,
                    "to": to,
                }
            ],
        )
        return json_rpc

    def test_get_params(self):
        """Test converting a json rpc request to an InputTransaction"""
        data = "0x93e3953900000000000000000000000000000000000000000000000000000000"
        json_rpc = self.build_input_json_rpc(data)
        parser = TransactionParser({})
        input_transaction = parser.get_params(json_rpc)
        self.assertEqual(input_transaction.to, json_rpc.params[0]["to"])
        self.assertEqual(input_transaction.data, data)

    def test_transaction_basic(self):
        """Test parsing a transaction for a simple contract method with one input"""
        contract = make_basic_contract()
        parser = TransactionParser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build valid raw transaction
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )

        json_rpc = self.build_input_json_rpc(payload.hex())
        res = parser.parse(json_rpc)

        self.assertEqual(res.contract_type, contract)
        self.assertEqual(res.contract_method.fn_name, "testmethod1")
        self.assertEqual(len(res.contract_method_args.keys()), 1)
        self.assertEqual(res.contract_method_args["_arg1"], 6)

    def test_transaction_multiple_args(self):
        """Test parsing a transaction for contract methods with several arguments"""
        contract = make_contract_multple_args(
            ["uint256", "address", "address", "uint256"]
        )
        parser = TransactionParser(
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

        json_rpc = self.build_input_json_rpc(payload.hex())
        res = parser.parse(json_rpc)

        self.assertEqual(res.contract_type, contract)
        self.assertEqual(res.contract_method.fn_name, "testmethod1")
        self.assertEqual(len(res.contract_method_args.keys()), 4)
        self.assertEqual(res.contract_method_args["_arg1"], 1)
        self.assertEqual(
            res.contract_method_args["_arg2"],
            "0x2222222222222222222222222222222222222222",
        )
        self.assertEqual(
            res.contract_method_args["_arg3"],
            "0x3333333333333333333333333333333333333333",
        )
        self.assertEqual(res.contract_method_args["_arg4"], 4)

        # build invalid raw transaction, has first argument, but no subsequent ones
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        )
        json_rpc = InputJsonRpc(
            method="",
            params=[
                {
                    "to": "0x1234123412341234123412341234123412341234",
                    "data": payload.hex(),
                }
            ],
        )

        self.assertRaises(ParseError, parser.parse, json_rpc)

    def test_transaction_invalid_contract(self):
        """Test parsing a transaction for an unrecognized contract"""
        contract = make_basic_contract()
        parser = TransactionParser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        # build invalid raw transaction, no contract at address 0x2222...
        payload = method_signature(contract.functions.testmethod1)
        payload += HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000006"
        )
        json_rpc = self.build_input_json_rpc(
            payload.hex(), "0x2222222222222222222222222222222222222222"
        )

        self.assertRaises(ParseError, parser.parse, json_rpc)

    def test_transaction_invalid_method_name(self):
        """Test that the parser fails when given a method name which doesn't exist"""
        contract = make_basic_contract()
        parser = TransactionParser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        payload = HexBytes(
            "0x343434340000000000000000000000000000000000000000000000000000000000000006",
        )
        json_rpc = self.build_input_json_rpc(payload.hex())
        self.assertRaises(ValueError, parser.parse, json_rpc)

    def test_transaction_no_method_args(self):
        """Test that the parser fails when no arguments are specified"""
        contract = make_basic_contract()
        parser = TransactionParser(
            {HexBytes("0x1234123412341234123412341234123412341234"): contract}
        )

        payload = method_signature(contract.functions.testmethod1)
        json_rpc = self.build_input_json_rpc(payload.hex())
        self.assertRaises(ParseError, parser.parse, json_rpc)


class TestMessageParser(TestCase):
    def build_input_json_rpc(
        self, message: str, to: str = "0x1234123412341234123412341234123412341234"
    ) -> InputJsonRpc:
        json_rpc = InputJsonRpc(
            method="eth_sign",
            params=[to, message],
        )
        return json_rpc

    def test_parse_message(self):
        """Test basic functionality of parse_message"""
        parser = MessageParser()

        original_message = "testmessage"
        message_hex = HexBytes(original_message.encode("ascii")).hex()
        parsed_message = parser.parse_message(message_hex)
        self.assertEqual(original_message, parsed_message)

    def test_parse_message_bad(self):
        """Make sure that parse_message raises an error if the hex is formatted badly"""
        parser = MessageParser()
        message_hex = "01X2Z340"
        self.assertRaises(ParseError, parser.parse_message, message_hex)

    def test_parse_basic(self):
        """Test basic functionality of parse"""
        parser = MessageParser()

        original_message = "testmessage"
        message_hex = HexBytes(original_message.encode("ascii")).hex()
        json_rpc = self.build_input_json_rpc(message_hex)
        parsed_message = parser.parse(json_rpc)
        self.assertEqual(original_message, parsed_message.message)

    def test_parse_bad(self):
        """Make sure that parse raises an error if the json rpc is bad"""
        parser = MessageParser()

        # no message
        json_rpc = InputJsonRpc(method="eth_sign", params=[])
        self.assertRaises(ParseError, parser.parse, json_rpc)
