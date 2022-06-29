import json
from web3 import Web3
from hexbytes import HexBytes
from typing import Any, Callable


class ContractType:
    def __init__(self, size : int, convert : Callable[[HexBytes], Any]):
        """
        typedef for allowed input types to functions
        """
        self.size = size
        self.convert = convert

contract_types = {
    "uint256" : ContractType(256//8, Web3.toInt),
    "address" : ContractType(20, Web3.toBytes)
}



class ABI_Method:
    def __init__(self, name: str, inputs: list[dict[str, str]]):
        self.name = name
        self.input_types = [item["type"] for item in inputs if "type" in item.keys()]
        self.input_names = [item["name"] for item in inputs if "name" in item.keys()]

    def hash(self) -> HexBytes:
        inputs = ",".join(self.input_types)
        return Web3.keccak(text=f"{self.name}({inputs})")[:4]


class ABI:
    def __init__(self, name: str, methods: list[ABI_Method]):
        self.name = name
        self.methods = {method.hash(): method for method in methods}
        self.method_names = {method.name: method for method in methods}


def ABI_from_json(name: str, filename: str) -> ABI:
    with open(filename, "r") as file_handle:
        data = json.load(file_handle)
        methods = []
        for method in data["abi"]:
            methods.append(ABI_Method(method["name"], method["inputs"]))
        return ABI(name, methods)


class InputTransaction:
    """
    Defines all of the required information for transaction inputs to policy engine
    """

    def __init__(self, to: HexBytes, data: HexBytes):
        self.to = to
        self.data = data


class ParsedTransaction:
    """
    Everything that should be in a parsed transaction
    """

    def __init__(
        self,
        to: HexBytes,
        data: HexBytes,
        contractType: ABI,
        method: ABI_Method,
        args: list[Any], # anything defined in contract_types
    ):
        self.to = to
        self.data = data
        self.contractType = contractType
        self.method= method
        self.args = args
