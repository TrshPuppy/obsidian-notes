
# Pointers
A pointer in coding is a data type which *holds the memory address of the data* it is pointing to (not the actual data).
## Defining & Using Pointers
> This will be using [golang](coding/languages/golang.md).

When dealing w/ pointers there are two common syntax elements you'll use/ see:
- `&` ampersand
- `*` asterisk/ dereference operator
### Ampersand (`&`)
When you place an ampersand `&` in front of a variable, you're telling the compiler you want to get the *address* of that variable. This means that you'll end up with a pointer.
### Dereference Operator (`*`)
When declaring a pointer variable, you use `*` in the declaration to make it a pointer type. In Go, the operator goes w/ the type in the declaration:
```go
var myPointer *int32 = &someInt
```
In this code, `myPointer` is declared with type `*int32` (pointer to an `int32` variable). Then, `myPointer` is initialized w/ the value of the address of `someint`.
### Example Program
Below is an example program. We'll use Go to create a string and a  pointer to that string. Then we'll print the values of the string and it's pointer:
```go
import fmt

func main() {
	var sharkString string = "shark"
	var stringPointer *string = &sharkString

	fmt.Println("sharkString = ", sharkString)
	fmt.Println("pointer to sharkString = ", stringPointer)
}
```
If we run this with `go run main.go`, we should get:
``` bash
sharkString = shark
pointer to sharkString = 0xc0000721e0
```
The pointer is a memory address represented in hexadecimal.
## Dereferencing
If we add a print line to the example above we can *dereference the pointer* to *get the value* at the address its pointing to:
```go
package main

import "fmt"

func main() {
	var sharkString string = "shark"
	var stringPointer *string = &sharkString

	fmt.Println("sharkString = ", sharkString)
	fmt.Println("pointer to sharkString = ", stringPointer)

	fmt.Println("*pointer =", *stringPointer) // <-----
}
```
The output should now be:
```bash
sharkString = shark
pointer to sharkString = 0xc0000721e0
*pointer = shark
```
This is called *dereferencing* because we're retrieving the value of the variable `sharkString` by using the dereference operator on the pointer.
### Using the pointer to change the value
If we want to change the *actual value* at its location in memory, then we can use the dereference operator:
```go
package main

import "fmt"

func main() {
	var sharkString string = "shark"
	var stringPointer *string = &sharkString

	fmt.Println("sharkString = ", sharkString)
	fmt.Println("pointer to sharkString = ", stringPointer)

	fmt.Println("*pointer = ", *stringPointer)

	*stringPointer = "jellyfish"
	fmt.Println("*pointer = ", *stringPointer)

	fmt.Println("sharkString = ", sharkString)
}
```
The output should be:
```bash
sharkString = shark
pointer to sharkString = 0xc0000721e0
*pointer = shark
*pointer = jellyfish
sharkString = jellyfish
```
**NOTICE** that the value of `sharkString` changed as well because we changed the actual data it references in memory.
## Function Pointer Receivers
When you pass variables to a function, they can either be *passed by value* of *passed by reference*. You can use the dereference operator to pass by reference, but you should only do that *if you're sure you want your function to change the actual value*.
### Passing by value
In Go, when you pass a value to a function, the function usually *creates a local copy of the data* instead of receiving the actual value as it is stored in memory. This is called *"passing by value"*. 

If the function changes the value at all, *it won't actually change the true value*, just the copy.
```go
package main

import "fmt"

type Creature struct {
	Species string
}

func main() {
	var creature Creature = Creature{Species: "shark"}

	fmt.Printf("1) %+v\n", creature)
	changeCreature(creature)
	fmt.Printf("3) %+v\n", creature)
}

func changeCreature(creature Creature) {
	creature.Species = "jellyfish"
	fmt.Printf("2) %+v\n", creature)
}
```
Output:
```bash
1) {Species:shark}
2) {Species:jellyfish}
3) {Species:shark}
```
You can see that the copy of `creature` was changed in the function, but the actual value was not.
### Passing by reference
If you want to manipulate the actual value, you can use the dereferencing operator `*`. By passing the *pointer* to the data, you're telling the function *where to find the data itself*. This is called *"passing by reference"*.
```go
package main

import "fmt"

type Creature struct {
	Species string
}

func main() {
	var creature Creature = Creature{Species: "shark"}

	fmt.Printf("1) %+v\n", creature)
	changeCreature(&creature)
	fmt.Printf("3) %+v\n", creature)
}

func changeCreature(creature *Creature) {
	creature.Species = "jellyfish"
	fmt.Printf("2) %+v\n", creature)
}
```
Output:
```bash
1) {Species:shark}
2) &{Species:jellyfish}
3) {Species:jellyfish}
```
Here, the change made to `creature` in the function *persisted beyond the scope of the function* because  it was *actually changed in memory*.
### Nil Pointers
In Go, when you define a variable but don't initialize it, the value will be `nil` until you set it. If you do this with a pointer type, it's called a *"nil pointer"* because it will also have a value of `nil`. You can think of nil as meaning *"nothing initialized"*.

If you try to dereference a nil pointer, nothing will be returned except for `nil`. When passing a nil pointer to a function, the result is the same; whatever work you try to do on that value will return `nil` because it and whatever properties you think it has doesn't exist yet.

When passing in pointers, you can check for a `nil` pointer. In the case you receive one, it's best to print an error line and return.
```go
...
func changeCreature(creature *Creature) {
	if creature == nil {
		fmt.Println("creature is nil") // <---
		return
	}

	creature.Species = "jellyfish"
	fmt.Printf("2) %+v\n", creature)
}
```
## Method Pointer Receivers
In Go, a receiver is the argument defined in the declaration of a method. Just like with functions, the behavior of the method as it relates to the receiver changes *depending on if its a value receiver or a pointer*.

If you pass the receiver *as a value*, then any changes made to it will not be made to *the instance of the type* that the method was defined on.
### Value Receiver example
In the following code we have a type `Creature` with a property `Species`. `Creature` has a method `Reset` which attempts to change the `Species` property:
```go
package main

import "fmt"

type Creature struct {
	Species string
}

func (c Creature) Reset() {
	c.Species = ""
}

func main() {
	var creature Creature = Creature{Species: "shark"}

	fmt.Printf("1) %+v\n", creature)
	creature.Reset()
	fmt.Printf("2) %+v\n", creature)
}
```
Because we're passing the receiver as a value the output looks like:
```bash
1) {Species:shark}
2) {Species:shark}
```
### Pointer Receiver example
```go
package main

import "fmt"

type Creature struct {
	Species string
}

func (c *Creature) Reset() {
	c.Species = ""
}

func main() {
	var creature Creature = Creature{Species: "shark"}

	fmt.Printf("1) %+v\n", creature)
	creature.Reset()
	fmt.Printf("2) %+v\n", creature)
}
```
Now that we've made the receiver *a pointer to `Creature`*, our output will be:
```bash
1) {Species:shark}
2) {Species:}
```
... because we've *ACTUALLY changed* the value of the `Species` property on this `Creature` instance.

> [!Resources]
> - [Digital Ocean: Understanding Pointers in Go](https://www.digitalocean.com/community/conceptual-articles/understanding-pointers-in-go)