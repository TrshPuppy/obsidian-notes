# YAML: Data Serialization language:
A language commonly used for configuration files and for applications to store or transmit data. It is similar to other mark up languages but uses python-styled indentation to indicate nesting (but *forbids tab characters* as indentation).
## Syntax:
YAML allows some custom data types and natively encodes *scalars* (strings, integers, floats), lists, and associative arrays (dictionaries, objects, etc.). 

Colon-separated syntax to denote key value pairs is taken from `RFC 822` which defines headers for [email](/networking/email.md). YAML documents are denotes with `---` as a document separator (similar to MIME `RFC 2046`). 
## Basic Components
### Conventional block format
New items in a list begin with a hyphen+space block format:
```YAML
--- # Favorite movies
- Casablanc
- North by Northwest
- The Man Who Wasn't There
```
### Inline formatting
Delimited by a comma+space and enclosed in brackets: (*like JSON*):
```YAML
--- # Shopping list
[milk, pumpkin pie, eggs, juice]
```
### Key-value pairs
Keys are separated from their values using a colon+space. Multiple pairs in one structure are separated using indentation and new lines. *Inline blocks* use comma+space to separate key value pairs b/w braces:
```YAML
--- # Indented Block
  name: John Smith
  age: 33
--- # Inline Block
{name: John Smith, age: 33}
```
### Strings
Strings *do not require quotations* and are instead demarcated using either a `|` to preserve new line characters or a `>` to "fold" newlines, both should be followed by a newline character:
```YAML
data: |
   There once was a tall man from Ealing
   Who got on a bus to Darjeeling
       It said on the door
       "Please don't sit on the floor"
   So he carefully sat on the ceiling
```
#### Newline and Whitespace
YAML will strip leading indentation of the first line as well as trailing white space, unless otherwise told (explicitly). Folded text will convert newlines to spaces and remove leading whitespace:
```YAML
data: >
   Wrapped text
   will be folded
   into a single
   paragraph

   Blank lines denote
   paragraph breaks
```
## Advanced Capabilities
What sets YAML apart from other data serialization languages are its structures and data typing. YAML structures allow storage of multiple documents in one file, using references for repeated "nodes", and using arbitrary nodes as keys.

YAML also provides *node anchors* (`&`) and *references* (`*`). The following code block is an example of a queue in which two steps are used multiple times without being fully described each time:
```YAML
--- # Sequencer protocols for Laser eye surgery
- step:  &id001                  # defines anchor label &id001
    instrument:      Lasik 2000
    pulseEnergy:     5.4
    pulseDuration:   12
    repetition:      1000
    spotSize:        1mm

- step: &id002
    instrument:      Lasik 2000
    pulseEnergy:     5.0
    pulseDuration:   10
    repetition:      500
    spotSize:        2mm
- Instrument1: *id001   # refers to the first step (with anchor &id001)
- Instrument2: *id002   # refers to the second step
```
### Data typing
YAML is able to autodetect data types but still allows a user to explicitly cast them. Casting can be done using an explicit *data type tag*. There are three categories of data types:
```YAML
---
a: 123                     # an integer
b: "123"                   # a string, disambiguated by quotes
c: 123.0                   # a float
d: !!float 123             # also a float via explicit data type prefixed by (!!)
e: !!str 123               # a string, disambiguated by explicit type
f: !!str Yes               # a string via explicit type
g: Yes                     # a boolean True (yaml1.1), string "Yes" (yaml1.2)
h: Yes we have No bananas  # a string, "Yes" and "No" disambiguated by context.
```
##### Core
Data types expected to already exist in a parser (strings, floats, ints, lists, maps...).
##### Defined
More advanced data types like binary data, etc. are defined in the YAML specification but are not available in every implementation. Built in types us a double exclamation *sigil* prefix:
```YAML
picture: !!binary |
  R0lGODdhDQAIAIAAAAAAANn
  Z2SwAAAAADQAIAAACF4SDGQ
  ar3xxbJ9p0qa7R0YxwzaFME
  1IAADs=
```
##### User-defined
YAML allows users to extend data type definitions locally into their own  classes, structures, or primitives. One example is *quad-precision floats.*

> [!Resources]
> - [Wikipedia: YAML](https://en.wikipedia.org/wiki/YAML)

