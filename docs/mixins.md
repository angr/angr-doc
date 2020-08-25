# What's Up With Mixins, Anyway?

If you are trying to work more intently with the deeper parts of angr, you will need to understand one of the design patterns we use frequently: the mixin pattern.

In brief, the mixin pattern is where python's subclassing features is used not to implement IS-A relationships (a Child is a kind of Person) but instead to implement pieces of functionality for a type in different classes to make more modular and maintainable code. Here's an example of the mixin pattern in action:

```python
class Base:
    def add_one(self, v):
        return v + 1
        
class StringsMixin(Base):
    def add_one(self, v):
        coerce = type(v) is str
        if coerce:
            v = int(v)
        result = super().add_one(v)
        if coerce:
            result = str(result)
        return result
        
class ArraysMixin(Base):
    def add_one(self, v):
        if type(v) is list:
            return [super().add_one(v_x) for v_x in v]
        else:
            return super().add_one(v)
        
class FinalClass(ArraysMixin, StringsMixin, Base):
    pass
```

With this construction, we are able to define a very simple interface in the `Base` class, and by "mixing in" two mixins, we can create the `FinalClass` which has the same interface but with additional features.
This is accomplished through python's powerful multiple inheritance model, which handles method dispatch by creating a _method resolution order_, or MRO, which is unsuprisingly a list which determines the order in which methods are called as execution proceeds through `super()` calls.
You can view a class' MRO as such:

```
FinalClass.__mro__

(FinalClass, ArraysMixin, StringsMixin, Base, object)
```

This means that when we take an instance of `FinalClass` and call `add_one()`, python first checks to see if `FinalClass` defines an `add_one`, and then `ArraysMixin`, and so on and so forth.
Furthermore, when `ArraysMixin` calls `super().add_one()`, python will skip past `ArraysMixin` in the MRO, first checking if `StringsMixin` defines an `add_one`, and so forth.

Because multiple inheritance can create strange dependency graphs in the subclass relationship, there are rules for generating the MRO and for determining if a given mix of mixins is even allowed. This is important to understand when building complex classes with many mixins which have dependencies on each other.
In short: left-to-right, depth-first, but deferring any base classes which are shared by multiple subclasses (the merge point of a diamond pattern in the inheritance graph) until the last point where they would be encountered in this depth-first search.
For example, if you have classes A, B(A), C(B), D(A), E(C, D), then the method resolution order will be E, C, B, D, A.
If there is any case in which the MRO would be ambiguous, the class construction is illegal and will throw an exception at import time.

This is complicated! If you find yourself confused, the canonical document explaining the rationale, history, and mechanics of python's multiple inheritence can be found [here](https://www.python.org/download/releases/2.3/mro/).

## Mixins in Claripy Solvers

yan please write something here

## Mixins in angr Engines

The main entry point to a SimEngine is `process()`, but how do we determine what that does?

The mixin model is used in SimEngine and friends in order to allow pieces of functionality to be reused between static and symbolic analyses.
The default engine, `UberEngine`, is defined as follows:

```python
class UberEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):
    pass
```

Each of these mixins provides either execution through a different medium or some additional instrumentation feature.
Though they are not listed here explicitly, there are some base classes implicit to this hierarchy which set up the way this class is traversed.
Most of these mixins inherit from `SuccessorsMixin`, which is what provides the basic `process()` implementation.
This function sets up the `SimSuccessors` for the rest of the mixins to fill in, and then calls `process_successors()`, which each of the mixins which provide some mode of execution implement.
If the mixin can handle the step, it does so and returns, otherwise it calls `super().process_successors()`.
In this way, the MRO for the engine class determines what the order of precedence for the engine's pieces is.

Let's take a closer look at the last mixin, `HeavyVEXMixin`.
If you look at the module hierarchy of the angr `engines` submodule, you will see that the `vex` submodule has a lot of pieces in it which are organized by how tightly tied to particular state types or data types they are.

TODO elaborate

## Mixins in the memory model

audrey please write something here. or fish, I'm not picky
