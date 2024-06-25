
Init.
# Type Systems in Programming
In programming, the concept of a 'type system' makes up a set of logical rules that define *type* as a property of the *symbols or terms* which make up the language.

These symbols and/ or terms are data constructs of the language such as variables, expressions, functions, etc.. A term's' type determines what type of data *it's allowed to represent/ hol.d.*  This helps prevent bugs.

Having a type system also helps enforce what operations can be done to variables or terms of that specific type. For example, in [golang](../languages/golang.md) if you attempt to pass an *int type* (a number) as a *string* type to a function which is expecting an int, the program will throw an error and won't be able to run. This would be a *type error*.

How or when a type error is thrown is determined by the *type system* of the programming language. For example, [python](../languages/python/python.md) doesn't enforce parameter types for a function  (unless you're using [ statically typed python](https://www.digitalocean.com/community/tutorials/python-typing-module). So if you pass a string value to a function that *you meant* to pass as an int, python will allow it and not throw a type error.
## Type Checking
Depending on how *strongly* or *weakly typed* a language is, enforcement of the rules of the type system has to be done at some point. Type checking can either be done *dynamically* at runtime, or *statically* at compile time. This is the difference between dynamically typed languages like python and [javascript](../languages/javascript.md), and statically typed languages like golang and [C](../languages/C.md).

Although most languages are primarily static or primarily dynamic, there are features which *can't be checked statically*. So, most languages will employ are a mix between being both dynamic and static type checking. In these languages, the static type checker will check what it can and the dynamic one will do the rest.
### Static Type Checking
In static type checking, the *type safety* of the *source code* is checked (before the program is compiled into [machine code](../languages/assembly.md)). A program's source code only passes if type checking if the type safety properties of all possible inputs are satisfied. Languages which are *'type-safe'* are better optimized because the compiler *does not need to perform dynamic safety checks* and the resulting binary will be smaller and run much faster.

Some statically typed languages give the option to *bypass the type checker* so the programmer can choose b/w dynamic and static type checking.  One such language is [C#](../languages/C-sharp.md).
### Dynamic Type Checking
In dynamic type checking, the type safety of the program is verified *at runtime* using *type tags*. Type tags are references to a  type which contains information about the type.

In dynamic type checking, the program is *expected to fail at runtime* if it cannot pass the type checking. Some of these failures can be handled in the code, while others are considered *fatal* to the program and will prevent it from finishing its execution.

> [!Resources]
> - [Digital Ocean: Python typing module](https://www.digitalocean.com/community/tutorials/python-typing-module)
> - [Wikipedia: Type  Systems](https://en.wikipedia.org/wiki/Type_system#Static_and_dynamic_type_checking_in_practice)