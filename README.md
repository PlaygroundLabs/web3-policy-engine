# web3-policy-engine

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/PlaygroundLabs/web3-policy-engine/tree/main.svg?style=svg&circle-token=ff2d46c95fc96fd5187127c3e3c89e990f64f285)](https://dl.circleci.com/status-badge/redirect/gh/PlaygroundLabs/web3-policy-engine/tree/main)


The goal of this project is to create a policy engine which judges transaction request (along with a list of user roles) and determines if the transaction should be signed and executed, or rejected.



## Example setup:

imports:
```python
from web3_policy_engine import PolicyEngine, PolicyEngineError
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
transactions:
  ERC20:
    approve:
      _spender:
        scholars_group1:
          - group1_manager
        scholars_group2:
          - group2_manager
    transferFrom:
      _sender:
        scholars_group1:
          - group1_manager
        scholars_group2:
          - group2_manager
      _recipient:
        scholars_group1:
          -group1_manager
        scholars_group2:
          -group2_manager

messages: {}

transaction_methods:
  - eth_signTransaction
  - eth_sendTransaction

message_methods:
  - eth_sign
```


Given the above configuration, you can build the policy engine with the following line:
```python
policy_engine = PolicyEngine("addresses.json", "permissions.yml", "groups.yml")
```

Test with a sample transaction, approving address 0x1021021021021021021021021021021021021021 to transfer 100 tokens.
```python
json_rpc = {
    "id": 1,
    "json_rpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "data": "0x095ea7b300000000000000000000000010210210210210210210210210210210210210210000000000000000000000000000000000000000000000000000000000000064",
      "from": "0x2222222222222222222222222222222222222222",
      "to": "0x1111111111111111111111111111111111111111",
      "gasPrice": "0x70657586c",
    }]
  }
```

to verify a transaction, call policy_engine.verify() with the transaction data and the list of roles. It will either return True, or raise an error. This example should be a good transaction.
```python
roles = ["group1_manager"]
try:
    policy_engine.verify(json_rpc, roles)
    print("Good transaction")
except PolicyEngineError:
    print("Wrong permissions")
```