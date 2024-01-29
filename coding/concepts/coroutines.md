
# Coroutines
To understand coroutines, let's establish the definition of a function. A function is a block of code which is called, does some work, and then returns back to the caller. When one function calls another function *the second function has to return* before the first function can continue.
![](/coding/coding-pics/coroutines-1.png)
> [Educative](https://www.educative.io/answers/what-is-a-coroutine)

A coroutine, on the other hand, can return to its caller at *multiple points in its execution*. To do this, coroutines *remember the exit point* of the first function as well as *the entry point* to the second function. So, when the first function starts is executing, and then *yields* control to the second function, the point at which the first function yields *will be remembered*. When the second function yields back to the first, execution of the first *will resume at the point that it first yielded*.
![](/coding/coding-pics/coroutines-2.png)

At each point that it returns to the caller, it pauses its execution at that point until it is called again, then picks up where it left off.
## Concurrency vs Parallelism
The difference b/w concurrency and parallelism is actually large. 
### Parallelism
In parallelism (in the context of programming), multiple tasks are *literally executing at the same time.* The tasks can be referred to as *independent* because their *independent* execution does not effect and is not effected by the other task/s.
### Concurrency
Concurrency differs from parallelism in that concurrent tasks are *interruptible*. In other words, one task is started, and then interrupted by the second. The second then is interrupted in order to resume the first, etc.. Given a window of time, the two tasks will be finished at the end of the timeframe, but do *not* finish consecutively (one after the other).

Coroutines are a perfect example of concurrency. In concurrency, the two tasks are switched between. This is achievable because the coroutines are capable of *remembering their exit and entrance points*. So, when one coroutine calls another, the execution of the first pauses at that point in its execution, and then resumes when the control is given back to it by the second coroutine.

> [!Resources]
> - [Educative: What is a Coroutine?](https://www.educative.io/answers/what-is-a-coroutine)
> - [Rob Pike: Concurrency is not Parallelism](https://vimeo.com/49718712)
> - [This Dev.to thread](https://dev.to/thibmaek/explain-coroutines-like-im-five-2d9)
> - [This StackOverflow thread](https://stackoverflow.com/questions/553704/what-is-a-coroutine/62162266#62162266)

