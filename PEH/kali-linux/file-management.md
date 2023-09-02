# Viewing, Creating, and Editing Linux Files

## Creating a file:
To create a file in Linux you can either use `touch` or you can `echo` contents into the file:
```bash
# touch creates an empty file
touch hey.txt
# echo will create a new file AND fill it with content:
echo "hello" > hey.txt
```

### Editing and Appending a file:
To edit or append to a file in Linux, you can use `>` & `>>`. The single `>` will overwrite the file and replace any data that's in there with whatever you type/ place to the right of the `>`.

The `>>` will also edit the file but will **append** the contents to the right of it to the end of the file.
```bash
echo "hello" > hey.txt
cat hey.txt
hello
echo "hello again" >> hey.txt
cat hey.txt
hello
hello again
```

## Text Editors:
### Terminal Text Editors:
Besides using `touch` and `echo` there are command-line text editors you can use which can do a lot more, such as searching through a text, copy pasting, jumping to line numbers, etc..

Three common CLI text editors are *nano*, *vi*, and *vim*. Terminal text editors are useful, especially if you are working in a system that has no GUI.

### Graphical Text Editors:
`mousepad` is a graphical text editor you can open from the command line. It's very similar to notepad on Windows machines.

`gedit` is similar to mousepad, but is deprecated.
