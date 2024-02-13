
# File Execution in Windows & Linux
Windows and Linux have very different ways of handling files, file extensions, and the execution of program files. While Windows relies heavily on file extensions to decide how to handle a file, Linux doesn't require them and only uses them to determine which program the user wants to use to open the file.

Application files (*executables*) are files which can be executed to run a process or program. Data files are files which hold data only, whether it be human-readable (like a `.txt`) or not (like a `.pdf`). 
## Windows
In Windows there are *multiple types* of executable files and Windows *uses the file extension* to decide what type of executables they are. For example, both `.exe` and `.bat` files are executable file types on Windows.

However, *any file can be executed*, the difference is that 'executing' some files on Windows really just *executes the executable associated with it*. For example, when you 'execute' a `.doc` file by clicking on it, Windows looks at the extension and then *executes the program associated with that extension*. So, in this case, Windows will execute `C:\Program Files\<blah blah>\winword.exe`.
## Linux
On Linux the execution of a file *is not determined by its extension*. In other words, whether or not a file is executable is *independent* of the extension it has. In fact, most executable files *don't have an extension*.

So how does Linux know how to execute a file w/o an extension? The *kernel* decides how to execute a file based on its contents. It natively already knows how to handle some file types. On types where it doesn't readily know, the *shebang can be used* to declare what interpreter should be used to execute the file. For example, this [python](coding/languages/python/python.md) script uses a shebang at the top to declare the python interpreter and where its located:
```python
#!/usr/bin/env python3

print("Your mom says hello!")
```
### Extensions on Linux
On Linux, most *data files have an extension* which indicates the type of data in the file. However, unlike Windows, the type of data (and thereby the extension) has *nothing to do with the application used to open it*. Because of this, multiple programs can be used/ designated to open specific file types.

For example, a `.pdf` can be opened w/ Okular, Xpdf, Qiv, etc.. When a file w/ an extension is ran, the *file manager consults a database* to find which application is *the preferred one* to open that file type.

> [!Resources]
> - [This StackExchange Question](https://unix.stackexchange.com/questions/266999/why-does-linux-use-file-extension-to-decide-the-default-program-for-opening-a-fi)
> - 