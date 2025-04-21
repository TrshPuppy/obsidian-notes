
# Visual Basic for Applications
INIT
## NameSpace
> [!Note]
> The following is an answer I got from an AI language model while studying for OSCP. I can't guarantee it's accurateness, but I'm leaving it here for my own reference. Hopefully I can re-write it myself later when I have time.

Yes, that's correct. In VBA, even if you declare a sub procedure or function with a lowercase name (not explicitly declared
as `Private`), it can still be accessed by other procedures within the same module or namespace.

This is because VBA uses a dynamic typing system, where objects and their members are resolved at runtime, rather than being
statically typed like some other programming languages.

When you declare a procedure with a lowercase name, such as `_MyProcedure()`, it's not explicitly marked as private. However,
if the procedure is declared within the same module or namespace as the code that calls it, VBA will still resolve the
procedure to the correct location at runtime.

To illustrate this, consider an example:
```vb
Module MyModule

    Sub _MyPrivateProcedure()
        ' Private procedure declaration not needed; still accessible
    End Sub

    Sub MyPublicProcedure()
        ' This can call _MyPrivateProcedure()
        _MyPrivateProcedure
    End Sub

End Module
```
In this example, `_MyPrivateProcedure()` is declared within the `MyModule` module. Although its name starts with an
underscore and a lowercase letter, it's still accessible from the `MyPublicProcedure()` subroutine because they're in the
same module.

However, if you were to try to access `_MyPrivateProcedure()` from another module or namespace (e.g., another module called
`OtherModule`), VBA would not find it. You'd get a `Type Mismatch` error or something similar, depending on how you've
declared the objects and procedures.

To make a procedure truly private, you need to explicitly declare it as `Private`, like this:
```vb
Module MyModule

    Private Sub _MyPrivateProcedure()
        ' Explicitly marked as private
    End Sub

End Module
```
Now, even if someone tries to access `_MyPrivateProcedure()` from outside the `MyModule` module, VBA will refuse to resolve
it.

> [!Resources]
> - Ollama: llama3.2