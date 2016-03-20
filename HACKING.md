# Developing angr

These are some guidelines so that we can keep the codebase in good shape!

We try to get as close as the [PEP8 code convention](http://legacy.python.org/dev/peps/pep-0008/) as is reasonable without being dumb.
If you use Vim, the [python-mode](https://github.com/klen/python-mode) plugin does all you need. You can also [manually configure](https://wiki.python.org/moin/Vim) vim to adopt this behavior.

Most importantly, please consider the following when writing code as part of angr:

- Try to use attribute access (see the `@property` decorator) instead of getters and setters wherever you can. This isn't Java, and attributes enable tab completion in iPython. That being said, be reasonable: attributes should be fast. A rule of thumb is that if something could require a constraint solve, it should not be an attribute.
- Use our `.pylintrc`. It's fairly permissive, but our CI server will fail your builds if pylint complains under those settings.
- DO NOT, under ANY circumstances, `raise Exception` or `assert False`. **Use the right exception type**. If there isn't a correct exception type, subclass the core exception of the module that you're working in (i.e. `AngrError` in angr, `SimError` in SimuVEX, etc) and raise that. We catch, and properly handle, the right types of errors in the right places, but `AssertionError` and `Exception` are not handled anywhere and force-terminate analyses.
- Avoid tabs; use space indentation instead. Even though it's wrong, the de facto standard is 4 spaces. It is a good idea to adopt this from the beginning, as merging code that mixes both tab and space indentation is awful.
- Avoid super long lines. It's okay to have longer lines, but keep in mind that long lines are harder to read and should be avoided. Let's try to stick to **120 characters**.
- Avoid extremely long functions, it is often better to break them up into smaller functions.
- Prefer `_` to `__` for private members (so that we can access them when debugging). *You* might not think that anyone has a need to call a given function, but trust us, you're wrong.
- **Document** your code. Every *class definition* and *public function definition* should have some description of:
 - What it does.
 - What are the type and the meaning of the parameters.
 - What it returns.
- If you're pushing a new feature, and it is not accompanied by a test case, it **will be broken** in very short order. Please write test cases for your stuff.
