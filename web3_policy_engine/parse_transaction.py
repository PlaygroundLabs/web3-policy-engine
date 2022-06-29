from hexbytes import HexBytes

# from eth_abi import decode

from .schemas import InputTransaction, ParsedTransaction, ABI, contract_types


class Parser:
    def __init__(self, contracts: dict[HexBytes, ABI]):
        self.contracts = contracts

    def parse(self, transaction: InputTransaction) -> ParsedTransaction | None:
        if transaction.to not in self.contracts:
            # address not in list of known contract types
            # raise ValueError("not in list of known contracts")
            return None
        contract = self.contracts[transaction.to]

        method_hash = transaction.data[:4]  # first 4 bytes
        if method_hash not in contract.methods:
            # method not in list of known methods for the specified contract
            # raise ValueError(f"{method_hash} not in list of known methods: {contract.methods}")
            return None
        method = contract.methods[method_hash]

        args = []
        i = 4
        for arg_type in method.input_types:
            if arg_type not in contract_types:
                raise ValueError(
                    f"Contract {contract.name} method {method.name} takes invalid type {arg_type}"
                )
            byte_len = contract_types[arg_type].size
            args.append(
                contract_types[arg_type].convert(transaction.data[i : i + byte_len])
            )
            i += byte_len

        return ParsedTransaction(
            transaction.to, transaction.data, contract, method, args
        )
