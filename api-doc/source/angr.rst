:mod:`angr` --- Analysis and Coordination
=========================================


Project
-------

.. automodule:: angr.project


Factory
-------

.. automodule:: angr.factory


Paths & Path Groups
-------------------

.. automodule:: angr.path
.. automodule:: angr.path_group
.. automodule:: angr.exploration_techniques
.. automodule:: angr.exploration_techniques.dfs
.. automodule:: angr.exploration_techniques.explorer
.. automodule:: angr.exploration_techniques.looplimiter
.. automodule:: angr.exploration_techniques.threading
.. automodule:: angr.exploration_techniques.veritesting
.. automodule:: angr.path_hierarchy
.. automodule:: angr.pathprioritizer

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
.. automodule:: angr.storage.file
.. automodule:: angr.storage.memory
.. automodule:: angr.plugins.symbolic_memory
.. automodule:: angr.plugins.abstract_memory
.. automodule:: angr.storage.memory_object
.. automodule:: angr.storage.paged_memory
.. automodule:: angr.concretization_strategies
.. automodule:: angr.sim_pcap
.. automodule:: angr.state_plugins.view

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
.. automodule:: angr.engines.unicorn_engine
.. automodule:: angr.engines.failure

Simulation Logging
------------------
.. automodule:: simuvex.s_action
.. automodule:: simuvex.s_action_object
.. automodule:: simuvex.s_event

Procedures
----------
.. automodule:: angr.sim_procedure
.. automodule:: angr.procedures
.. automodule:: angr.misc.format_parser

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

.. automodule:: angr.analysis
.. automodule:: angr.annocfg
.. automodule:: angr.analyses
.. automodule:: angr.analyses.backward_slice
.. automodule:: angr.analyses.bindiff
.. automodule:: angr.analyses.boyscout
.. automodule:: angr.analyses.cdg
.. automodule:: angr.analyses.cfg_accurate
.. automodule:: angr.analyses.cfg_base
.. automodule:: angr.analyses.cfg_fast
.. automodule:: angr.analyses.cfg_node
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
.. automodule:: angr.sim_slicer

SimOS
-----

.. automodule:: angr.simos


Surveyors
---------

Do not use surveyors. They are a legacy interface.

.. automodule:: angr.surveyor
.. automodule:: angr.surveyors
.. automodule:: angr.surveyors.caller
.. automodule:: angr.surveyors.escaper
.. automodule:: angr.surveyors.executor
.. automodule:: angr.surveyors.explorer
.. automodule:: angr.surveyors.slicecutor
