:mod:`claripy` --- Solver Engine
================================

Realistically, you should never have to work with in-depth claripy APIs unless you're doing some hard-core analysis.
Most of the time, you'll be using claripy as a simple frontend to z3::

    import claripy
    a = claripy.BVS("sym_val", 32)
    b = claripy.RotateLeft(a, 8)
    c = b + 4
    s = claripy.Solver()
    s.add(c == 0x41424344)
    assert s.eval(c, 1)[0] == 0x41424344
    assert s.eval(a, 1)[0] == 0x40414243

Or using its components in angr::

    import angr, claripy
    b = angr.Project('/bin/true')
    path = b.factory.path()
    rax_start = claripy.BVS('rax_start', 64)
    path.state.regs.rax = rax_start
    path_new = path.step()[0]
    rax_new = path_new.state.regs.rax
    path_new.state.se.add(rax_new == 1337)
    print(path_new.state.se.eval(rax_start, 1)[0])
 

AST
---
.. automodule:: claripy.ast
.. automodule:: claripy.ast.base
.. automodule:: claripy.ast.bits
.. automodule:: claripy.ast.bool
.. automodule:: claripy.ast.bv
.. automodule:: claripy.ast.fp
.. automodule:: claripy.ast.int
.. automodule:: claripy.ast.strings
.. automodule:: claripy.ast.vs


Backends
--------

.. automodule:: claripy.backends
.. automodule:: claripy.backend_manager
.. automodule:: claripy.backend_object
.. automodule:: claripy.backends.backend_concrete
.. automodule:: claripy.backends.backend_z3
.. automodule:: claripy.backends.backend_z3_parallel
.. automodule:: claripy.backends.celeryconfig
.. automodule:: claripy.backends.backend_vsa
.. automodule:: claripy.backends.backend_smtlib_solvers.z3str_popen
.. automodule:: claripy.backends.backend_smtlib_solvers.cvc4_popen
.. automodule:: claripy.backends.backend_smtlib_solvers.z3_popen
.. automodule:: claripy.backends.backend_smtlib_solvers.abc_popen
.. automodule:: claripy.backends.backend_smtlib_solvers
.. automodule:: claripy.backends.backend_smtlib
 

Frontends
---------

.. automodule:: claripy.frontend
.. automodule:: claripy.frontends
.. automodule:: claripy.frontends.composite_frontend
.. automodule:: claripy.frontends.constrained_frontend
.. automodule:: claripy.frontends.full_frontend
.. automodule:: claripy.frontends.hybrid_frontend
.. automodule:: claripy.frontends.light_frontend
.. automodule:: claripy.frontends.replacement_frontend
.. automodule:: claripy.solvers


Frontend Mixins
---------------
.. automodule:: claripy.frontend_mixins
.. automodule:: claripy.frontend_mixins.composited_cache_mixin
.. automodule:: claripy.frontend_mixins.concrete_handler_mixin
.. automodule:: claripy.frontend_mixins.constraint_deduplicator_mixin
.. automodule:: claripy.frontend_mixins.constraint_expansion_mixin
.. automodule:: claripy.frontend_mixins.constraint_filter_mixin
.. automodule:: claripy.frontend_mixins.constraint_fixer_mixin
.. automodule:: claripy.frontend_mixins.debug_mixin
.. automodule:: claripy.frontend_mixins.eager_resolution_mixin
.. automodule:: claripy.frontend_mixins.model_cache_mixin
.. automodule:: claripy.frontend_mixins.sat_cache_mixin
.. automodule:: claripy.frontend_mixins.simplify_helper_mixin
.. automodule:: claripy.frontend_mixins.simplify_skipper_mixin
.. automodule:: claripy.frontend_mixins.solve_block_mixin
.. automodule:: claripy.frontend_mixins.eval_string_to_ast_mixin
.. automodule:: claripy.frontend_mixins.smtlib_script_dumper_mixin


Annotations
-----------
.. automodule:: claripy.annotation


VSA
---

.. automodule:: claripy.vsa
.. automodule:: claripy.vsa.abstract_location
.. automodule:: claripy.vsa.bool_result
.. automodule:: claripy.vsa.discrete_strided_interval_set
.. automodule:: claripy.vsa.errors
.. automodule:: claripy.vsa.strided_interval
.. automodule:: claripy.vsa.valueset


Misc. Things
------------


.. automodule:: claripy
.. automodule:: claripy.balancer
.. automodule:: claripy.bv
.. automodule:: claripy.errors
.. automodule:: claripy.fp
.. automodule:: claripy.operations
.. automodule:: claripy.simplifications
.. automodule:: claripy.ops
.. automodule:: claripy.smtlib_utils
.. automodule:: claripy.strings
.. automodule:: claripy.debug
