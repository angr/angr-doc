:mod:`angr` --- Analysis and Coordination
=========================================


Project
-------

.. automodule:: angr.project
.. automodule:: angr.factory

Program State
-------------
.. automodule:: angr.sim_state
.. automodule:: angr.sim_options
.. automodule:: angr.state_plugins
.. automodule:: angr.state_plugins.inspect
.. automodule:: angr.state_plugins.libc
.. automodule:: angr.state_plugins.posix
.. automodule:: angr.state_plugins.solver

Storage
-------
.. automodule:: angr.storage
.. automodule:: angr.state_plugins.view
.. automodule:: angr.storage.file
.. automodule:: angr.storage.memory
.. automodule:: angr.state_plugins.symbolic_memory
.. automodule:: angr.state_plugins.abstract_memory
.. automodule:: angr.storage.memory_object
.. automodule:: angr.storage.paged_memory
.. automodule:: angr.concretization_strategies

Simulation Manager
------------------

.. automodule:: angr.manager
.. automodule:: angr.exploration_techniques
.. automodule:: angr.exploration_techniques.dfs
.. automodule:: angr.exploration_techniques.explorer
.. automodule:: angr.exploration_techniques.looplimiter
.. automodule:: angr.exploration_techniques.threading
.. automodule:: angr.exploration_techniques.veritesting
.. automodule:: angr.state_hierarchy
.. automodule:: angr.pathprioritizer

Simulation Engines
------------------

.. automodule:: angr.engines
.. automodule:: angr.engines.engine
.. automodule:: angr.engines.successors
.. automodule:: angr.engines.vex
.. automodule:: angr.engines.vex.engine
.. automodule:: angr.engines.procedure
.. automodule:: angr.engines.hook
.. automodule:: angr.engines.syscall
.. automodule:: angr.engines.unicorn
.. automodule:: angr.engines.failure

Simulation Logging
------------------
.. automodule:: angr.state_plugins.sim_action
.. automodule:: angr.state_plugins.sim_action_object
.. automodule:: angr.state_plugins.sim_event

Procedures
----------
.. automodule:: angr.sim_procedure
.. automodule:: angr.procedures
.. automodule:: angr.procedures.stubs.format_parser

Calling Conventions and Types
-----------------------------
.. automodule:: angr.calling_conventions
.. automodule:: angr.sim_variable
.. automodule:: angr.sim_type
.. automodule:: angr.type_backend

Knowledge Base
--------------

.. automodule:: angr.knowledge_base
.. automodule:: angr.knowledge
.. automodule:: angr.knowledge.codenode
.. automodule:: angr.knowledge.data
.. automodule:: angr.knowledge.function
.. automodule:: angr.knowledge.function_manager
    :members: FunctionManager


Analysis
--------

.. automodule:: angr.analyses
.. automodule:: angr.analyses.analysis
.. automodule:: angr.analyses.backward_slice
.. automodule:: angr.analyses.bindiff
.. automodule:: angr.analyses.boyscout
.. automodule:: angr.analyses.cdg
.. automodule:: angr.analyses.cfg.cfg_accurate
.. automodule:: angr.analyses.cfg.cfg_base
.. automodule:: angr.analyses.cfg.cfg_fast
.. automodule:: angr.analyses.cfg.cfg_node
.. automodule:: angr.analyses.code_location
.. automodule:: angr.analyses.datagraph_meta
.. automodule:: angr.analyses.ddg
.. automodule:: angr.analyses.dfg
.. automodule:: angr.analyses.forward_analysis
.. automodule:: angr.analyses.girlscout
.. automodule:: angr.analyses.loopfinder
.. automodule:: angr.analyses.veritesting
.. automodule:: angr.analyses.vfg
.. automodule:: angr.analyses.vsa_ddg
.. automodule:: angr.blade
.. automodule:: angr.slicer
.. automodule:: angr.annocfg

SimOS
-----

.. automodule:: angr.simos
