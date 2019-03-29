:mod:`angr` --- Analysis and Coordination
=========================================

.. automodule:: angr

Project
-------

.. automodule:: angr.project
.. automodule:: angr.factory
.. automodule:: angr.block

Plugin Ecosystem
----------------

.. automodule:: angr.misc.plugins

Program State
-------------
.. automodule:: angr.sim_state
.. automodule:: angr.sim_options
.. automodule:: angr.sim_state_options
.. automodule:: angr.state_plugins
.. automodule:: angr.state_plugins.plugin
.. automodule:: angr.state_plugins.inspect
.. automodule:: angr.state_plugins.libc
.. automodule:: angr.state_plugins.posix
.. automodule:: angr.state_plugins.filesystem
.. automodule:: angr.state_plugins.solver
.. automodule:: angr.state_plugins.log
.. automodule:: angr.state_plugins.callstack
.. automodule:: angr.state_plugins.fast_memory
.. automodule:: angr.state_plugins.light_registers
.. automodule:: angr.state_plugins.history
.. automodule:: angr.state_plugins.gdb
.. automodule:: angr.state_plugins.cgc
.. automodule:: angr.state_plugins.trace_additions
.. automodule:: angr.state_plugins.globals
.. automodule:: angr.state_plugins.uc_manager
.. automodule:: angr.state_plugins.scratch
.. automodule:: angr.state_plugins.preconstrainer
.. automodule:: angr.state_plugins.unicorn_engine
.. automodule:: angr.state_plugins.loop_data
.. automodule:: angr.state_plugins.concrete
.. automodule:: angr.state_plugins.keyvalue_memory
.. automodule:: angr.state_plugins.javavm_classloader
.. automodule:: angr.state_plugins.jni_references
.. automodule:: angr.state_plugins.javavm_memory
.. automodule:: angr.state_plugins.heap
.. automodule:: angr.state_plugins.heap.heap_base
.. automodule:: angr.state_plugins.heap.heap_brk
.. automodule:: angr.state_plugins.heap.heap_freelist
.. automodule:: angr.state_plugins.heap.heap_libc
.. automodule:: angr.state_plugins.heap.heap_ptmalloc
.. automodule:: angr.state_plugins.heap.utils


Storage
-------

.. automodule:: angr.storage
.. automodule:: angr.state_plugins.view
.. automodule:: angr.storage.file
.. automodule:: angr.storage.memory
.. automodule:: angr.state_plugins.symbolic_memory
.. automodule:: angr.state_plugins.abstract_memory
.. automodule:: angr.storage.kvstore
.. automodule:: angr.storage.memory_object
.. automodule:: angr.storage.pcap
.. automodule:: angr.storage.paged_memory
.. automodule:: angr.concretization_strategies

Concretization Strategies
-------------------------

.. automodule:: angr.concretization_strategies.single
.. automodule:: angr.concretization_strategies.eval
.. automodule:: angr.concretization_strategies.norepeats
.. automodule:: angr.concretization_strategies.solutions
.. automodule:: angr.concretization_strategies.nonzero_range
.. automodule:: angr.concretization_strategies.range
.. automodule:: angr.concretization_strategies.max
.. automodule:: angr.concretization_strategies.norepeats_range
.. automodule:: angr.concretization_strategies.nonzero
.. automodule:: angr.concretization_strategies.any
.. automodule:: angr.concretization_strategies.controlled_data


Simulation Manager
------------------

.. automodule:: angr.sim_manager
.. automodule:: angr.state_hierarchy

Exploration Techniques
----------------------

.. automodule:: angr.exploration_techniques
.. automodule:: angr.exploration_techniques.dfs
.. automodule:: angr.exploration_techniques.explorer
.. automodule:: angr.exploration_techniques.lengthlimiter
.. automodule:: angr.exploration_techniques.manual_mergepoint
.. automodule:: angr.exploration_techniques.spiller
.. automodule:: angr.exploration_techniques.threading
.. automodule:: angr.exploration_techniques.veritesting
.. automodule:: angr.exploration_techniques.tracer
.. automodule:: angr.exploration_techniques.driller_core
.. automodule:: angr.exploration_techniques.slicecutor
.. automodule:: angr.exploration_techniques.director
.. automodule:: angr.exploration_techniques.oppologist
.. automodule:: angr.exploration_techniques.loop_seer
.. automodule:: angr.exploration_techniques.cacher
.. automodule:: angr.exploration_techniques.stochastic
.. automodule:: angr.exploration_techniques.unique
.. automodule:: angr.exploration_techniques.tech_builder
.. automodule:: angr.exploration_techniques.common
.. automodule:: angr.exploration_techniques.symbion
.. automodule:: angr.exploration_techniques.memory_watcher

Simulation Engines
------------------

.. automodule:: angr.engines
.. automodule:: angr.engines.engine
.. automodule:: angr.engines.successors
.. automodule:: angr.engines.hub
.. automodule:: angr.engines.vex
.. automodule:: angr.engines.vex.engine
.. automodule:: angr.engines.procedure
.. automodule:: angr.engines.hook
.. automodule:: angr.engines.syscall
.. automodule:: angr.engines.unicorn
.. automodule:: angr.engines.failure
.. automodule:: angr.engines.concrete
.. automodule:: angr.engines.soot
.. automodule:: angr.engines.soot.engine

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
.. automodule:: angr.procedures.definitions

Calling Conventions and Types
-----------------------------
.. automodule:: angr.calling_conventions
.. automodule:: angr.sim_variable
.. automodule:: angr.sim_type
.. automodule:: angr.type_backend
.. automodule:: angr.callable

Knowledge Base
--------------

.. automodule:: angr.knowledge_base
.. automodule:: angr.knowledge_plugins
.. automodule:: angr.knowledge_plugins.plugin
.. automodule:: angr.knowledge_plugins.comments
.. automodule:: angr.knowledge_plugins.data
.. automodule:: angr.knowledge_plugins.indirect_jumps
.. automodule:: angr.knowledge_plugins.labels
.. automodule:: angr.knowledge_plugins.functions
.. automodule:: angr.knowledge_plugins.functions.function_manager
    :members: FunctionManager
.. automodule:: angr.knowledge_plugins.functions.function
.. automodule:: angr.knowledge_plugins.functions.soot_function
.. automodule:: angr.knowledge_plugins.variables
.. automodule:: angr.knowledge_plugins.variables.variable_access
.. automodule:: angr.knowledge_plugins.variables.variable_manager
.. automodule:: angr.keyed_region


Analysis
--------

.. automodule:: angr.analyses
.. automodule:: angr.analyses.analysis
.. automodule:: angr.analyses.forward_analysis
.. automodule:: angr.analyses.backward_slice
.. automodule:: angr.analyses.bindiff
.. automodule:: angr.analyses.boyscout
.. automodule:: angr.analyses.calling_convention
.. automodule:: angr.analyses.soot_class_hierarchy
.. automodule:: angr.analyses.cfg
.. automodule:: angr.analyses.cfg.cfb
.. automodule:: angr.analyses.cfg.cfg
.. automodule:: angr.analyses.cfg.cfg_emulated
.. automodule:: angr.analyses.cfg.cfg_base
.. automodule:: angr.analyses.cfg.cfg_fast
.. automodule:: angr.analyses.cfg.cfg_node
.. automodule:: angr.analyses.cfg.cfg_arch_options
.. automodule:: angr.analyses.cfg.cfg_job_base
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.x86_pe_iat
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.mips_elf_fast
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.x86_elf_pic_plt
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.default_resolvers
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.jumptable
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.resolver
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers
.. automodule:: angr.analyses.cfg.cfg_utils
.. automodule:: angr.analyses.cfg.memory_data
.. automodule:: angr.analyses.cfg.cfg_fast_soot
.. automodule:: angr.analyses.cdg
.. automodule:: angr.analyses.code_location
.. automodule:: angr.analyses.datagraph_meta
.. automodule:: angr.analyses.code_tagging
.. automodule:: angr.analyses.decompiler.structurer
.. automodule:: angr.analyses.decompiler
.. automodule:: angr.analyses.decompiler.clinic
.. automodule:: angr.analyses.decompiler.decompiler
.. automodule:: angr.analyses.decompiler.optimization_passes
.. automodule:: angr.analyses.decompiler.optimization_passes.optimization_pass
.. automodule:: angr.analyses.decompiler.optimization_passes.stack_canary_simplifier
.. automodule:: angr.analyses.decompiler.structured_codegen
.. automodule:: angr.analyses.decompiler.region_identifier
.. automodule:: angr.analyses.decompiler.region_simplifier
.. automodule:: angr.analyses.ddg
.. automodule:: angr.engines.light.data
.. automodule:: angr.engines.light
.. automodule:: angr.engines.light.engine
.. automodule:: angr.analyses.reaching_definitions.uses
.. automodule:: angr.analyses.reaching_definitions.undefined
.. automodule:: angr.analyses.reaching_definitions.definition
.. automodule:: angr.analyses.reaching_definitions.constants
.. automodule:: angr.analyses.reaching_definitions.atoms
.. automodule:: angr.analyses.reaching_definitions.engine_vex
.. automodule:: angr.analyses.reaching_definitions.reaching_definitions
.. automodule:: angr.analyses.reaching_definitions
.. automodule:: angr.analyses.reaching_definitions.dataset
.. automodule:: angr.analyses.reaching_definitions.engine_ail
.. automodule:: angr.analyses.reaching_definitions.external_codeloc
.. automodule:: angr.analyses.stack_pointer_tracker
.. automodule:: angr.analyses.variable_recovery.annotations
.. automodule:: angr.analyses.variable_recovery.variable_recovery_base
.. automodule:: angr.analyses.variable_recovery.variable_recovery_fast
.. automodule:: angr.analyses.variable_recovery.variable_recovery
.. automodule:: angr.analyses.variable_recovery
.. automodule:: angr.analyses.identifier.identify
.. automodule:: angr.analyses.loopfinder
.. automodule:: angr.analyses.loop_analysis
.. automodule:: angr.analyses.veritesting
.. automodule:: angr.analyses.vfg
.. automodule:: angr.analyses.vsa_ddg
.. automodule:: angr.analyses.disassembly
.. automodule:: angr.analyses.disassembly_utils
.. automodule:: angr.analyses.reassembler
.. automodule:: angr.analyses.congruency_check
.. automodule:: angr.analyses.static_hooker
.. automodule:: angr.analyses.binary_optimizer
.. automodule:: angr.analyses.callee_cleanup_finder
.. automodule:: angr.analyses.dominance_frontier
.. automodule:: angr.blade
.. automodule:: angr.slicer
.. automodule:: angr.annocfg
.. automodule:: angr.codenode


SimOS
-----

.. automodule:: angr.simos
.. automodule:: angr.simos.simos
.. automodule:: angr.simos.linux
.. automodule:: angr.simos.cgc
.. automodule:: angr.simos.userland
.. automodule:: angr.simos.windows
.. automodule:: angr.simos.javavm

Utils
-----
.. automodule:: angr.utils
.. automodule:: angr.utils.constants
.. automodule:: angr.utils.graph
.. automodule:: angr.utils.library

Errors
------
.. automodule:: angr.errors

Serialization
-------------
.. automodule:: angr.vaults
