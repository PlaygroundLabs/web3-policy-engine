Usage
=====

.. _installation:

Installation
------------

Install using poetry:

.. code-block:: console

    poetry install


Policy engine
-------------

To instantiate a policy engine using files for all configurations:

.. autofunction:: web3_policy_engine.PolicyEngine.from_file

To verify incoming requests, use verify_transaction and verify_message:

.. automethod:: web3_policy_engine.PolicyEngine.verify_transaction
.. automethod:: web3_policy_engine.PolicyEngine.verify_message


Parser
------

In case you want to parse a transaction, but not verify it, a Parser may be used.

.. autoclass:: web3_policy_engine.parse_transaction.Parser
.. automethod:: web3_policy_engine.parse_transaction.Parser.__init__
.. automethod:: web3_policy_engine.parse_transaction.Parser.parse_transaction
