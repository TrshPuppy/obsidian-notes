---
aliases:
  - thread
  - threads
---

# Threading
Threads are the *smallest executable subunits* which make up a [process](/computers/concepts/process.md). Processes can have multiple threads and one main thread. They're most often used to *take full advantage* of the [CPU](../../computers/concepts/CPU.md) and avoid idle CPU time.
## Multithreading
Without threads and multithreading, the tasks which make up a process can block each other, pausing the execution of a program until a single process has returned. For example, If you're writing a word document using a graphical program, when you save the document, the program has to pause execution in order to *write your document to disk*. 

If threads/ multithreading isn't being used, then the graphical portion of your program will appear to stall while the program waits for the document to finish being written to the disk. Since the CPU isn't used for writing to the disk, the CPU *is idle* during this time.

Multithreading makes use of this idle time. Instead of having the program execute on one thread, the program can be given two threads, one for rendering the graphical interface, and one for writing to the disk. So, in a multithreaded version of our program, when you save your document, the thread handling the graphics will be scheduled on the CPU so the program won't stall while the IO thread writes to the disk.
### Thread Pools
A thread pool is a pool of threads (`-_-`) which is made up of a bunch of 'worker threads'. These workers are assigned to execute a task and then *returned to the pool* when they've finished. The threads in the pool are usually served tasks via a *queue*. When a task is in the queue and a thread in the pool is free, it will inherit the task from the queue.
#### Advantages to thread pools:
Thread pools are advantageous for a few reasons, most of which having to do with the threads being ready-made as opposed to being created when needed.
1. The time b/w a queued task becoming available and then being processed by a thread is zero b/c there is no time wasted in creating a thread.
2. The system won't run out of memory because the thread pool is created to fit the needs of the program.
3. The previous point also means that we won't overwhelm the system with process threads.
4. A thread pool can replace a thread if it dies unexpectedly  due to an exception
### Locking
In a multithreaded environment, it's important to be able to lock a resource to a single thread. In other words, you can 'lock' a resource by only allowing a single thread to access it at one time.
#### Mutex
A mutex is just another word for 'lock'. It stands for 'mutually exclusive.' In computer science, mutual exclusion is the requirement that multiple concurrent threads *cannot access a critical resource* while another thread *is already accessing it.* Mutual exclusion helps prevent [race conditions](/coding/bugs/race-condition.md) because it *locks* the shared resource to one thread instead of allowing multiple threads to access it (and potentially change it).

There are different types of locks, but most commonly *advisory locks* are used.
##### Advisory Locks
An advisory lock is one in which the thread *must acquire the lock before accessing the resource*. The thread is *blocked* until it's allowed to access the resource. This type of lock is efficient *depending on how long it takes for the lock to become available*, and what the thread is doing while it's waiting.

For example, 'spin locks' are locks which have the thread *wait* (spin) until the lock becomes available. If the thread doesn't have to wait very long, this is considered efficient. If it has to wait a long time, it's inefficient.

> [!Resources]
> - [Wikipedia: Mutual Exclusion](https://en.wikipedia.org/wiki/Mutual_exclusion)
> - [Wikipedia: Locks](https://en.wikipedia.org/wiki/Lock_(computer_science)#Mutexes_vs._semaphores)
> - [Educative: Multithreading and Concurrency Fundamentals](https://www.educative.io/blog/multithreading-and-concurrency-fundamentals)

