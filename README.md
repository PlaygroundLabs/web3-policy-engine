# web3-policy-engine

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/PlaygroundLabs/web3-policy-engine/tree/main.svg?style=svg&circle-token=ff2d46c95fc96fd5187127c3e3c89e990f64f285)](https://dl.circleci.com/status-badge/redirect/gh/PlaygroundLabs/web3-policy-engine/tree/main)


The goal of this project is to create a policy engine which judges transaction request (along with a list of user roles) and determines if the transaction should be signed and executed, or rejected.



## Example setup:

imports:
```python
from hexbytes import HexBytes
from web3 import Web3

from web3_policy_engine import (InputTransaction,
                                InvalidPermissionsError,
                                PolicyEngine)
```

addresses.json (this simulates a database):
```json
{
    "contract_names" : {
        "ERC20" : "ERC20.json"
    },
    "addresses" : {
	"0x1111111111111111111111111111111111111111": "ERC20"
    }
}
```

groups.yml (this also simulates a database):
```yaml
scholars_group1:
  - "0x1021021021021021021021021021021021021021"
  - "0x1031031031031031031031031031031031031031"
  - "0x1041041041041041041041041041041041041041"
  - "0x1051051051051051051051051051051051051051"
  - "0x1061061061061061061061061061061061061061"
scholars_group2:
  - "0x2032032032032032032032032032032032032032"
  - "0x2042042042042042042042042042042042042042"
  - "0x2052052052052052052052052052052052052052"
  - "0x2062062062062062062062062062062062062062"
  - "0x2072072072072072072072072072072072072072"
```


## permissions.yml:
```yaml
ERC20:
  approve:
    - manager:
        _spender:
          - scholars_group1
          - scholars_group2
  transferFrom:
    - manager:
        _sender:
          - scholars_group1
          - scholars_group2
        _recipient:
          - scholars_group1
          - scholars_group2
    - scholar_group1:
        _sender:
          - scholars_group1
        _recipient:
          - scholars_group1
    - scholar_group2:
        _sender:
          - scholars_group2
        _recipient:
          - scholars_group2
```


Given the above configuration, you can build the policy engine with the following line:
```python
policy_engine = PolicyEngine("addresses.json", "permissions.yml", "groups.yml")
```

Building a transaction using web3 is a little tricky. Fortunately, this step is only used for testing, as in deployment, raw transactions are inputted
```python
# get ERC20 contract from the policy engine
# (this address defined to be an ERC20 contract in addresses.json)
contract_address = bytes(HexBytes("0x1111111111111111111111111111111111111111"))
ERC20 = policy_engine.parser.contracts[contract_address]

def get_transaction_data(sender: bytes, receiver: bytes) -> bytes:
    # set some dummy transaction parameters for building the transaction later
    tx_params = {
        "gas": 100000000,
        "maxFeePerGas": 100000000,
        "maxPriorityFeePerGas": 100000000,
        "chainId": 420,
        "to": Web3.toChecksumAddress(contract_address),
    }

    # build a transaction, and compute the raw data
    transaction = ERC20.functions.transferFrom(sender, receiver, amount)
    tx_data = transaction.buildTransaction(tx_params)["data"]
    return tx_data
```

to verify a transaction, call policy_engine.verify() with the transaction data and the list of roles. It will either return True, or raise an error.
```python
try:
    policy_engine.verify(InputTransaction(contract_address, tx_data), roles)
    print("Good transaction")
except InvalidPermissionsError:
    print("Wrong permissions")
```