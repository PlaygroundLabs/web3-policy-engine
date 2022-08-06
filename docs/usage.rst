Usage
=====

.. _installation:

Installation
------------

Install using poetry:
.. code-block:: console

    poetry install


Permission Configuration
------------------------

Any .yml file configuring permissions must contain the following for variables:

.. code-block:: yaml

    transactions: {}
    messages: {}
    transaction_methods: []
    message_methods: []

Currently, all incoming requests are assumed to either use transactions or messages (for signing). Transactions are configured as follows:

.. code-block:: yaml

    transactions:
        contract_name:
            method_name:
                argument_name:
                    option:
                        - allowed_role

Creating a policy engine
------------------------

To create a policy engine using files for all configurations:

.. autofunction:: web3_policy_engine.PolicyEngine.from_file

