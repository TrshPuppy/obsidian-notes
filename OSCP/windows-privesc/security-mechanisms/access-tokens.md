---
aliases:
  - access tokens
---
# Access Tokens
Once a user is authenticated, Windows generates an access token and assigns it to the user. The access token *contains info* pertaining to the *security context* of the user. The security context is made up of a few rules and attributes which are in effect for the user:
- the [SID](SID.md) of the user
- *SIDs of the groups* they belong to
- the user's privileges
- the groups' privileges
- the scope of the token
## Primary & Impersonation Tokens
### Primary Tokens
Once a user starts a process or thread, *a token will be assigned to it*. This token is called a *primary token*. This token determines the permissions the thread or process has when interacting w/ other objects. The primary token *copies the user's access token*. 
## Impersonation Tokens
Threads can be assigned impersonation tokens which are used to *provide a different security context* from the process' (which owns the thread). The thread uses the impersonation token  to interact with processes *on behalf of the impersonation token* instead of on behalf of the process' token. 

> [!Resources]
> - [Microsoft: Impersonation Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-tokens)
> - My [own notes](https://github.com/trshpuppy/obsidian-notes) linked throughout the text.