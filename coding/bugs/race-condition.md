
# Race Condition
A race condition in software development refers to an unanticipated bug which occurs when multiple executing processes finish at unexpected times. 

If the code is expecting a specific order for these processes to finish in relation to each other, but that order is different at execution, this causes a race condition and comes w/ security implications.

This commonly occurs when independent processes depend on some shared state. If different processes operate on a shared state it is best practice to make sure they are *mutually exclusive*.

An example of a race condition is when two light switches control a single light. If two people try to switch the lights at the same time, one instruction might cancel another or the circuit breaker might trip.
## Types
### File Based
When multiple processes attempt to access and modify the same file simultaneously. When this happens, it can cause *data corruption*, unauthorized access, and other unintended/ unanticipated problems.
### TOCTTOU
*Time-of-Check-to-Time-of-Use*: In this type of race condition there is a time delay b/w when an application checks a resource and when it uses it. This can cause security concerns involving *data manipulation*.
### Database
When multiple queries/ transactions are sent to a database at the same time, this can cause data to be inconsistent and can also lead to *unauthorized access*.
## Security
Race conditions in software can be leveraged by an attacker. The bugs caused by race conditions can allow an attacker to perform any number of attacks including [denial-of-service](cybersecurity/TTPs/exploitation/denial-of-service.md),[README](../../cybersecurity/TTPs/actions-on-objective/privesc/README.md), etc.. 

A specific attack based on race conditions is a 0TOCTTOU (time-of-check-to-time-of-use). This bug usually involves *authentication*. A window of time between when an auth value is checked and when it's used is opened, allowing for exploitation.

> [!Resources]
> - [Wikipedia: Race Condition](https://en.wikipedia.org/wiki/Race_condition#Computer_security)
> - [Tech Target: Race Condition](https://www.techtarget.com/searchstorage/definition/race-condition)
> - [Wikipedia: TOCTTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
> - [Karthikeyan Nagaraj: Understanding Race Conditions... in Web Apps](https://cyberw1ng.medium.com/understanding-race-conditions-vulnerabilities-in-web-app-penetration-testing-2023-a821710012b2)



