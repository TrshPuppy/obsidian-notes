
# Central Processing Unit (CPU)
The CPU of a computer is the main *processor* of said computer. It includes circuitry which *executes instructions of a program*. These instructions include arithmetic, logic, controlling, and input/ output operations.
## Components
The design and implementation of CPUs has changed over time, but the primary components remain the same:
### Arithmetic Logic Unit (ALU)
Performs arithmetic and bitwise logic operations on binary numbers. The ALU takes two inputs: the *operand* (which is the data to be operated on), and the *code indicating the operation to be performed*. The output is the result of the operation.
### Processor Registers
Supplies operands to the ALU. Also stores the results of operations done by the ALU. They are *quickly accessible* locations which hold data that the processor can access. Can be considered as "fast storage" for the CPU.
### Control Unit
Coordinates and directs the operation of the ALU and registers, and thereby the execution of instructions. Also fetches data from memory and handles decoding of each instruction.
#### Fetching
Fetching refers to the retrieval of an instruction from *program memory*. The address which the instruction is located at is saved by the [instruction pointer](coding/languages/assembly.md) (in Intel x86 microprocessors). Once the instruction is fetched, the instruction pointer or "PC" *is incremented by the length of the fetched instruction*. This is so the instruction pointer is now holding the address of the following instruction.
#### Decoding
Decoding in this context refers to the conversion of an instruction into signals which control other parts of the CPU
## Microprocessors
Microprocessors are the *most common implementation of a CPU*.

> [!Resources]
> - [Wikipedia: Central Processing Unit](https://en.wikipedia.org/wiki/Central_processing_unit#Decode)
> - [Wikipedia: ALU](https://en.wikipedia.org/wiki/Arithmetic_logic_unit)
> - [Wikipedia: Processor Register](https://en.wikipedia.org/wiki/Processor_register)