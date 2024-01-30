

These are my notes I wrote for Asyncio while watching [Tib3rius' YT video](https://www.youtube.com/watch?v=1vhu5VUv2tk). Tibs was trying to help me out with writing my python CLI tool [NetPuppy](https://github.com/TrshPuppy/NetPuppy). I learned a lot about processes, threading, and concurrency (it was actually very eye-opening). So please, check out his [channel](https://www.youtube.com/@Tib3rius); he is a cybersecurity badass and has put out a lot of solid & free educational material on hacking and coding.
# Learning the Asyncio Python Lib
[Asyncio](https://realpython.com/async-io-python/#async-io-explained) is a library in [python](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/languages/python/python.md) used for asynchronous coding. Similar to other languages, like [JavaScript](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/languages/javascript.md), it uses an `async`/ `await` syntax. In addition to providing a framework to run asynchronous code, it also provides APIs which handle coroutines, subprocesses, network I/O, task queueing, and even synchronizing concurrent code (among other things).
## [Coroutines](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/concepts/coroutines.md)
Coroutines are functions which are asynchronous and can be run concurrently. Coroutines *DO NOT* run in parallel. Instead, they are functions which can pause their own execution to *yield* execution control to another function. They can then *resume* execution when they're called again by another coroutine.

With the asyncio lib, we can start and complete multiple tasks in a shorter amount of time by using concurrency. Instead of tasks being executed consecutively, asyncio has methods which allow us to start one task, then start another task before the first one returns.
## Asyncio Walkthrough
```python
import asyncio, time

async def coroutine(name, delay):
    print(f"{name} + Starting")
    await asyncio.sleep(delay)
    print(f"{name} + Finished")

    return name + ":" + str(delay) + " second delay"

async def main():
    start_time = time.time()

    await coroutine("Coroutine 1", 5)
    await coroutine("Coroutine 2", 3)

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
As this is written, these two coroutines will *NOT* run concurrently because of the *await keyword*. This keyword is telling the program to *await the return* of the first call to `coroutine()` before moving on to the second call of `coroutine()`. Similarly, even without the `await` keyword, these two coroutines will still have to run consecutively (one after the other). So, the output will look like this:
```bash
Coroutine 1 Starting
Coroutine 1 Finished
Coroutine 2 Starting
Coroutine 2 Finished
Time: 8.0107
```
### Asyncio `create_task`
With the asyncio library you can run two coroutines at the same time by using *tasks*. With tasks, you're defining 2 or more tasks to asyncio, then awaiting those tasks but the difference is *when you `await` an asyncio task, it 'returns' immediately* (as in the rest of your code can resume instead of having to wait for the task too return).
```python
import asyncio, time

async def coroutine(name, delay):
    print(f"{name} + Starting")
    await asyncio.sleep(delay)
    print(f"{name} + Finished")

    return name + ":" + str(delay) + " second delay"

async def main():
	task1 = asyncio.create_task(coroutine("Coroutine 1", 5))
	task2 = asyncio.create_task(coroutine("Coroutine 2", 3))
    start_time = time.time()

    await task1 # returns immediately
    await task2 # starts when task1 returns

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
Notice that the `coroutine()` function has it's own `await`; *this is when the tasks will yield control flow*. So, when `task1` is called, it will `print(f"{name} + Starting")` then `await asyncio.sleep(delay)` (delay for `task1` is 5 seconds). When it hits this `await` line, `task1` will *yield control to `task2`*. `task2` will then start, *attempt* to yield control back to `task1`, but since `task1`'s delay is longer, control will be yielded back to `task2`. `task2` finishes first because its delays is only 3 seconds.

So, if we edit our original code to define the variables `task1` and `task2` and set their values using asyncio's `create_task()` method, then we can run both tasks 'concurrently' by awaiting them. 
```bash
Coroutine 1 Starting
Coroutine 2 Starting
Coroutine 2 Finished # remember Coroutine 2 is 3 seconds
Coroutine 1 Finished
Time: 5.003
```
### Asyncio `gather()`
The `gather()` method of the Asyncio lib can be used to 'gather' asyncio tasks and return their return values as a list. The tasks will still be run concurrently.

`gather()` is useful because if you have multiple tasks running asynchronously they're unlikely to finish at the same time. So, instead of printing their results as they finish, `gather()` allows you to wait until they're all finished and then will print the results *in the order that you gave them to `gather()`*.
```python
...
# the code above this line is the same as the other examples
async def main():
	task1 = asyncio.create_task(coroutine("Coroutine 1", 5))
	task2 = asyncio.create_task(coroutine("Coroutine 2", 3))
    start_time = time.time()

    results = asyncio.gather(task1, task2)
    print(f"Results: {', '.join(results)}")

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
Now, we're 'gathering' the two tasks into our variable `results`. `results` will end up being a *list of the results* from both tasks. We then print `results` as a string w/ each value joined by a comma and space (`' ,'`).
```bash
Coroutine 1 Starting
Coroutine 2 Starting
Coroutine 2 Finished # remember Coroutine 2 is 3 seconds
Coroutine 1 Finished
Results: Coroutine 1: 5 second delay, Coroutine 2: 3 second delay
Time: 5.006
```
### Asyncio `wait()`
One downside of using `gather()` is you have to wait for all of the gathered tasks to return before you can know their results. If instead you want to see results as they return, you can use aysncio's `wait()`.

`wait()` returns two values which are both lists. The first value is a list of *completed tasks*. The second is a list of *tasks which are still running*. Instead of waiting for the results of the task, we're going to use a while loop and `wait()` to get results from our tasks as they finish:
```python
...
# no changes above this line
async def main():
	task1 = asyncio.create_task(coroutine("Coroutine 1", 5))
	task2 = asyncio.create_task(coroutine("Coroutine 2", 3))
	pending = [task1, task2] # create a list of the two tasks
    
    start_time = time.time()

	while pending: # while there are tasks in pending
		done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

		for task in done:
			print(f"Result: {task.result()})

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
We're also adding some new asyncio parameters which are being used in `wait()`.
- `return_when` is a keyword (given as the 2nd parameter here) whose value tells asyncio how to return tasks which are `done`.
- `FIRST_COMPLETED` is the value of `return_when` and is telling `wait()` to return a task to `done` *as soon as any pending tasks return*.
So, to break down the while loop; while there are pending tasks in the `pending` list, await `aysncio.wait()`. `wait()` is being told to return as soon as one of the pending tasks returns. The first task which finishes (during this iteration of the while loop) will be pushed to the `done` list by `wait()`

Once a pending task returns, we iterate over `done` in a for loop and print the results. Then, if there are still tasks pending, the while loop starts over. It will continue until there are no more pending tasks.
```bash
Coroutine 1 Starting
Coroutine 2 Starting
Coroutine 2 Finished # remember Coroutine 2 is 3 seconds
Result: Coroutine 2: 3 second delay
Coroutine 1 Finished
Results: Coroutine 1: 5 second delay
Time: 5.006
```
#### Giving `wait()` a timeout
If you give `wait()` a timeout parameter, then our while loop changes a bit. Let's say we give `wait()` a timeout of `1` (1 second). Now, our while loop will iterate every `1 second` because we're telling `wait()` to wait for 1 second *at max* for a task to return.

Additionally, we'll add some conditional logic. Before looping through our `done` list, we'll check first to make sure it actually has any completed tasks in it. *If it does* we'll print the results. *Else*, we'll print 'Timed out!' (no tasks completed before the 1 second timeout started by the while loop, so `done` is empty).
```python
# no changes above this line
async def main():
	task1 = asyncio.create_task(coroutine("Coroutine 1", 5))
	task2 = asyncio.create_task(coroutine("Coroutine 2", 3))
	pending = [task1, task2] # create a list of the two tasks
    
    start_time = time.time()

	while pending: # while there are tasks in pending
		done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

		if done:
			for task in done:
				print(f"Result: {task.result()})
		else:
			print('Timed out!')

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
The output should look like this:
```bash
Coroutine 1 Starting
Coroutine 2 Starting
Timed out!
Timed out!
Coroutine 2 Finished # remember Coroutine 2 is 3 seconds
Result: Coroutine 2: 3 second delay
Timed out!
Coroutine 1 Finished
Results: Coroutine 1: 5 second delay
Time: 5.006
```
### Getting Fancy w/ `wait()`
Let's say you have more coroutines and you want to start them based on the results of an earlier coroutine? You can do this by pushing and removing tasks from the `pending` list *from within* our while loop.

For example, let's add a third task called `Coroutine 3`. We only want our task to execute depending on the result of `Coroutine 1`:
```python
# no changes above this line
async def main():
	task1 = asyncio.create_task(coroutine("Coroutine 1", 5))
	task2 = asyncio.create_task(coroutine("Coroutine 2", 3))
	
	pending_tasks = [task1, task2] # create a list of the two tasks
    
    start_time = time.time()

	while pending_tasks: # while there are tasks in pending
		done, pending = await asyncio.wait(pending_tasks, return_when=asyncio.FIRST_COMPLETED)

		for task in done:
			current_result = task.result()
			print(f"Result: {task.result()}")
			
			if current_result.startswith('Coroutine 1'):
				task3 = asyncio.create_task(coroutine('Coroutine 3', 5))
				pending_tasks.append(task3)
			
			pending_tasks.remove(task) # note: not the same as 'pending'

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
In this code, we added `pending_tasks` which is our own list of tasks that we're checking separately from `pending` (which is being checked and changed by `wait()`). In our while loop, we're now iterating over the list of `done` tasks.

For each task in `done` we grab the result and check it. If the result meets our conditional, then we *start a new task*: `task3`. We then add our new task to `pending_tasks` and remove the old task. Since `pending_tasks` is being checked by the while loop, and then given to `asyncio.wait()`, our loop will still continue until all of the tasks our finished (including the new ones we add).
```bash
Coroutine 1 Starting
Coroutine 2 Starting
Coroutine 2 Finished
Result: Coroutine 2: 3 second delay
Coroutine 1 Finished
Results: Coroutine 1: 5 second delay
Coroutine 3 Starting # Coroutine 3 starts b/c Coroutine 1 just finished
Coroutine 3 Finished
Result: Coroutine 3: 5 second delay
Time: 10.011
```
## Processes w/ `create_subprocess_shell()`
What we've done w/ Asyncio so far is try to get as close to concurrency as possible using [coroutines](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/concepts/coroutines.md). In Python, true concurrency and [threading](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/concepts/threading.md) is nearly impossible due to Python's [Global Interpreter Lock](https://en.wikipedia.org/wiki/Global_interpreter_lock) (GIL). Evidently, Python is [unable to handle thread safety](https://www.infoworld.com/article/3685373/is-it-finally-time-to-remove-the-python-gil.html) and so it implements a GIL to enforce *mutual exclusion*.
### Mutual Exclusion
[Mutual Exclusion](https://github.com/TrshPuppy/obsidian-notes/blob/main/coding/concepts/coroutines.md) (or "mutex") is a concept in computer science which dictates how a thread accesses a resource. With a mutex, a resource can only be accessed *by one thread at a time*.

Python's GIL is a *global mutex lock*, so true threading and concurrency is not actually supported by the language itself. Python *attempts* to get around this with subprocesses.
### Subprocesses
If you think of a 'program' as an executable file, then a [process](https://github.com/TrshPuppy/obsidian-notes/blob/main/computers/concepts/process.md) is a currently-executing *instance* of a program. For example, if you open a Firefox window, you've started the process which executes the Firefox program/ executable.

A process can further be broken down into *threads* which are the smallest executable units of a process. Processes usually have multiple threads with one main thread. Processes commonly use *multithreading* to implement concurrency and avoid idle CPU time (while waiting for a task to finish)
.

Since Python can't do this (there are caveats, I'm sure), most programmers instead use *multiprocessing* in order to achieve something which looks sort of like multithreading in Python. So, instead of having two threads (with different tasks) run concurrently, we spawn two *processes* and run those concurrently. If we assign each task to a new process, then those processes can be run concurrently w/o encountering the mutex block of the GIL.

We can do that using asyncio's `create_subprocess_shell()` method.
```python
import asyncio, time

async def execute(cmd, name):
    print(f"{name} + Starting")
    process = await asyncio.create_subprocess_shell(
	    cmd,
	    stdin=None,
	    stdout=asyncio.subprocess.PIPE,
	    stderr=asyncio.subprocess.PIPE,
	    executable='/bin/bash')

	await process.wait()
	print(f"{name} + Finished")
	return process

async def main():
	# Create task1 & task2 which will be process objects:
	task1 = asyncio.create_task(execute('sleep 5; echo "Command 1"', 'Command 1'))
	task2 = asyncio.create_task(execute('sleep 3; echo "Command 2"', 'Command 2'))
	pending_tasks = [task1, task2] 
    
    start_time = time.time()

	while pending_tasks:
		done, pending = await asyncio.wait(pending_tasks, return_when=asyncio.FIRST_COMPLETED)

		for task in done:
			print('Return Code: ' + str(task.result().returncode))
			
			lines = []
			while not task.result().stdout.at_eof(): # while the stdout is not empty
				line = (await task.result().stdout.readline()).deconde('utf-8)
				lines.append(line)
			
			print('Output: ' + '\n'.join(lines))
			ending_tasks.remove(task) # note: not the same as 'pending'

    end_time = time.time() - start_time
    print("Time: " + str(end_time))
```
In this code, we've replaced the `coroutine()` function w/ `execute()` which takes a command and its name. Then, in `main()` we create two tasks which are actually processes created and returned by `execute()`.

In our while loop we use `wait()` again to collect tasks as they finish. When a task finishes, we start a second while loop which will loop until the  `stdout.at_eof()` is empty (we've read all of the lines in the `stdout` file of the process). We push each line into the `lines` list which we then print to the console to see the output of the process.

The output should look like this:
```bash
Command 1 Starting
Command 2 Starting
Comamnd 2 Finished
Return Code: 0
Output: Command 2

Command 1 Finished
Return Code: 0
Output: Command 1

Time: 5.008
```
Compared w/ the first way we made concurrent tasks in asyncio (using `create_task` and `await`), now we've achieved 'parallel' execution of our tasks by turning them into *independent processes*. Since they are independent, they won't be blocked by the GIL and can start and finish their tasks regardless of what the other is doing.
# Conclusion
Asyncio is a complex lib and there is a lot more to it, but this was enough for me, personally, to get started. If you want to read up on more computer science comcepts, I've linked my personal notes throughout, as well as the following resources (which I used):

> [!Resources]
> - [Tib3rius: Geeking Out Over Python & Asyncio](https://www.youtube.com/watch?v=1vhu5VUv2tk)
> - [This Dev.to thread](https://dev.to/thibmaek/explain-coroutines-like-im-five-2d9)
> - [Educative: Multithreading and Concurrency Fundamentals](https://www.educative.io/blog/multithreading-and-concurrency-fundamentals)
> - [InfoWorld: Is it Finally Time to Remove the Python GIL?](https://www.infoworld.com/article/3685373/is-it-finally-time-to-remove-the-python-gil.html)

![](writeups/writeup-pics/asyncio-1.png)