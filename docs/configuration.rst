Configuration
=============

The primary permissions configuration of the policy engine is typically stored in a permissions yaml file (See :ref:`permissions`). In addition, there are two auxiliary configurations that may be specified:

1. :ref:`groups`
2. :ref:`contracts`


.. _permissions:

Permissions
------------------------

Any .yml file configuring permissions must contain the following four variables:

.. code-block:: yaml

    transactions: {}
    messages: {}
    transaction_methods: []
    message_methods: []

Currently, all incoming requests are assumed to either use transactions or messages.

Messages are configured as follows:

.. code-block:: yaml

    messages:
        message_plaintext:
            - allowed_role

Note that the message is written in plaintext (e.g. "text" not "0x74657874")

Transactions are configured as follows:

.. code-block:: yaml

    transactions:
        contract_name:
            method_name:
                argument_name:
                    option:
                        - allowed_role

All eth functions expected to be used should be listed in transaction_methods and message_methods respectively.

.. code-block:: yaml

    transaction_methods:
        - eth_signTransaction
        - eth_sendTransaction

    message_methods:
        - eth_sign

    


.. _groups:

Argument groups
------------------------

It is frequently helpful to group several arguments under one category, making the permissions configuration easier and more flexible.
Argument groups allow you to avoid allowing a list of addresses individually (which would be cumbersome and difficult to maintain across several contracts).
Instead, separate the group listing into an argument group, meaning that in the permissions configuration, only one line is needed to allow the entire group.
Changes in a group will be reflected in the policy engine without modification to the permissions configuration.

This library supports specifing argument groups through json or yaml files. Linking an argument group to a database is not supported out of the box, but can be extended.

Loading argument groups from files is done with the argument_groups_from_yaml function:

.. autofunction:: web3_policy_engine.loader.argument_groups_from_yaml

All argument groups must inherit from the base ArgumentGroup class.

.. autoclass:: web3_policy_engine.contract_common.ArgumentGroup
.. automethod:: web3_policy_engine.contract_common.ArgumentGroup.__init__
.. automethod:: web3_policy_engine.contract_common.ArgumentGroup.contains

To add custom argument groups (e.g. to link argument groups to a database), extend the ArgumentGroup class:

.. code-block:: python

    class DatabaseArgumentGroup(ArgumentGroup):
        def __init__(self, database, table):
            self.database = database
            self.table = table
        
        def contains(self, item):
            res = self.database.query(self.table).filter(self.table.item == item).one_or_none()
            if res is None:
                return False
            return True


And make a new initializer for the policy engine which implements the new class

.. code-block:: python

    def from_file_database(
        contract_addresses: str,
        permissions_config: str,
        database: Database,
        argument_groups: dict[str, Type[Table]],
    ) -> PolicyEngine:
        """
        argument_groups maps group names to sqlalchemy-style tables
        """
        contracts, addresses = contract_addresses_from_json(contract_addresses)
        groups = {
            group_name: DatabaseArgumentGroup(database, table)
            for group_name, table in argument_groups.items()
        }
        return PolicyEngine(contracts, addresses, groups, permissions_config)


.. _contracts:

Contracts and contract addresses
--------------------------------

For each contract type described in the permissions configuration, an ABI for the contract must be loaded.
Additionally, all deployments of smart contracts must be registered, so that the address is recognized.

The provided function to load this information from a file is contract_addresses_from_json:

.. autofunction:: web3_policy_engine.loader.contract_addresses_from_json
