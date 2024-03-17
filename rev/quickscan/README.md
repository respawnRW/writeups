# Cyber Apocalypse 2024

# Quickscan | medium

> In order to escape this alive, you must carefully observe and analyze your opponents. Learn every strategy and technique in their arsenal, and you stand a chance of outwitting them. Just do it fast, before they do the same to you...

## Overview

The challenge is as follows: we are given 128 pieces of base64-encoded ELF files, which load a value onto the stack. We need to send back the loaded value as a hex string. This challenge is a bit similar to one of the challenges currently active on HackTheBox, so won't talk about it or name it at all. My initial thoughts were to let's grab those ELF binaries, run them with Qiling or Unicorn, and exfiltrate what we need from the stack in a similar fashion. However, wasn't necessary and that was overcomplicating things. In the beginning the challenge's required response time was 30 seconds, then this got increased to 60, then later on to 120 seconds to be more lenient to those with higher latency. 

Connecting with netcat this is what we can see:

```bash
nc 94.237.49.166 38409

I am about to send you 128 base64-encoded ELF files, which load a value onto the stack.
You must send back the loaded value as a hex string
You must analyze them all in under 60 seconds
Let's start with a warmup
ELF:  f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAwIMECAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAgAQIAAAAAACABAgAAAAA3AMAAAAAAADcAwAAAAAAAAAQAAAAAAAA75nGcdFXm3WcBzhwh0kpWB5fE9NZL8e7U9JtanQc/AJXayHqDkMGWiRH38W6jAbVVCg8WSpCIaike2vxCLuLFVEWoqlz/rNUA2+85HGr8zYn6heZ2s8BNxbqXuOBW/rZ6mVk/x95I7DnFXDDbc4KAnsX5b3o6uO2usGzqWFIpKlxLaNwJRcSKLXF8NmGElDdFJEvGAsPU8xmHu3EoyiOtELc/SiIhUsAxi23QJPzNHlO6RLzyU40+8ndsg7jq+2DC9Ir/mrquCYGGBO9zMnuIqJuxHyYzK6ZUbrWDow+ikyn3IOXXK3/qZV/OZ+xT3vMaMxoV/eL0313NLapkRIJZGeEhlzgTjpkakrPPeWRFzw0fZMlyL9+GRuBbmZ1tiz/3g35DxqEka3TI3eOxYBN7LSPZ0g5CnWgIIfDjzUKR51TiecAY0pJCV9rHWynvoLQLAj7wFt8tZnbNd+bxYLcMhT34KhPs9lv7twncEXqCGrA9s8BfP6OJyK+Okfmy4HPd7sCBWRBpWfyNs6/9nT+fhKcQ/148z0qB6w6lE03VpVvwpiErWuDLHjXY9EQ2hx3qyordQLPFnI4t0r4EEk62Wr7cI8JEQVABw0rCsjU9U+mJNDKko4v9zAGPw5hRY208DQlK+IeyN8udRy34butAQuzC42p0wrpdVnQfBoLJIi0HEQefrfjhk8dCstWl6bU9NxH3puLiscxHMItOjDtiyXlsJm/wDgfpQvHrLiS76Og4hvEBxNxGExbhXixNMUyN6sCiaKqR6HRlvrw1YaZTrpm9kchLwZm17cJWXgYMsLnlrbjbLxPPuaNdhvgin3plGsxjPdf15Rxb0ieS0kTGRtw+OzzTSg9YNnmI8ezbJFdPPxVpGocToE2dMBvbM/B3Ou32vrCxZl3ynAw3T3S0N8kZIWJe+Gf46oMhO4/AxY9wozAnwB53hldVSI8MFcEAjvFqT7G8ZqHCgLgDxVJzn/M5bv/PEqBtC/uidkXjXcFnVzpp6tXoFanBj8JREnifBF5LamZtbqlVWH/CWuI4oGL7EW81AI2Pd2uM8vvrOCloyTkfZuWg4t7bUjNfCya0EORD2fE51zUnTk0iuj/EX6k71qSr1hqSIPsGEiNNSj///9Iiee5GAAAAPOkuDwAAAAPBQ==
Expected bytes: 9e4b4913191b70f8ecf34d283d60d9e623c7b36c915d3cfc
Bytes? 
```

## Solution

Despite our gut feeling or first impression, considering to run each ELF file in a sandboxed environment to observe its behavior directly, is not a good solution. It is overly complex, time-consuming, and not efficient at all, especially given the tight time window. That is our strategy is from a disassembling and analysis standpoint. But first let's just grab the first ELF, decode the base64 string back into its original binary form. 

```python
import base64

# The base64-encoded ELF string
elf_b64 = "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAwIMECAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAgAQIAAAAAACABAgAAAAA3AMAAAAAAADcAwAAAAAAAAAQAAAAAAAA75nGcdFXm3WcBzhwh0kpWB5fE9NZL8e7U9JtanQc/AJXayHqDkMGWiRH38W6jAbVVCg8WSpCIaike2vxCLuLFVEWoqlz/rNUA2+85HGr8zYn6heZ2s8BNxbqXuOBW/rZ6mVk/x95I7DnFXDDbc4KAnsX5b3o6uO2usGzqWFIpKlxLaNwJRcSKLXF8NmGElDdFJEvGAsPU8xmHu3EoyiOtELc/SiIhUsAxi23QJPzNHlO6RLzyU40+8ndsg7jq+2DC9Ir/mrquCYGGBO9zMnuIqJuxHyYzK6ZUbrWDow+ikyn3IOXXK3/qZV/OZ+xT3vMaMxoV/eL0313NLapkRIJZGeEhlzgTjpkakrPPeWRFzw0fZMlyL9+GRuBbmZ1tiz/3g35DxqEka3TI3eOxYBN7LSPZ0g5CnWgIIfDjzUKR51TiecAY0pJCV9rHWynvoLQLAj7wFt8tZnbNd+bxYLcMhT34KhPs9lv7twncEXqCGrA9s8BfP6OJyK+Okfmy4HPd7sCBWRBpWfyNs6/9nT+fhKcQ/148z0qB6w6lE03VpVvwpiErWuDLHjXY9EQ2hx3qyordQLPFnI4t0r4EEk62Wr7cI8JEQVABw0rCsjU9U+mJNDKko4v9zAGPw5hRY208DQlK+IeyN8udRy34butAQuzC42p0wrpdVnQfBoLJIi0HEQefrfjhk8dCstWl6bU9NxH3puLiscxHMItOjDtiyXlsJm/wDgfpQvHrLiS76Og4hvEBxNxGExbhXixNMUyN6sCiaKqR6HRlvrw1YaZTrpm9kchLwZm17cJWXgYMsLnlrbjbLxPPuaNdhvgin3plGsxjPdf15Rxb0ieS0kTGRtw+OzzTSg9YNnmI8ezbJFdPPxVpGocToE2dMBvbM/B3Ou32vrCxZl3ynAw3T3S0N8kZIWJe+Gf46oMhO4/AxY9wozAnwB53hldVSI8MFcEAjvFqT7G8ZqHCgLgDxVJzn/M5bv/PEqBtC/uidkXjXcFnVzpp6tXoFanBj8JREnifBF5LamZtbqlVWH/CWuI4oGL7EW81AI2Pd2uM8vvrOCloyTkfZuWg4t7bUjNfCya0EORD2fE51zUnTk0iuj/EX6k71qSr1hqSIPsGEiNNSj///9Iiee5GAAAAPOkuDwAAAAPBQ=="

# Decode the base64 string
elf_binary = base64.b64decode(elf_b64)

# Write the binary content to a file
with open("decoded_binary", "wb") as binary_file:
    binary_file.write(elf_binary)
```

Alright, so we got the decoded_binary in its binary form. Launch your favorite disassembler and try to find what's up with that binary. In my example below, I'm using Ghidra. We are interested in how does the data gets imported into the stack.

![image](https://github.com/respawnRW/writeups/assets/163560495/d009dcf6-dca5-48a2-bbe6-669b1dd188e7)

Rest of the data in the binary is lots of junk and clutter, those do not matter. Let's see what happens line-by-line basic.

```asm
SUB    RSP,0x18                   ; Subtract from the stack pointer to allocate space on the stack.
LEA    RSI,[DAT_0804831b]         ; Load the effective address of the data labeled as 'DAT_0804831b' into RSI.
MOV    RDI,RSP                    ; Move the stack pointer address into RDI.
MOVSB.REP RDI,RSI=DAT_0804831b    ; Move string byte from RSI to RDI with repeat prefix (could be a part of a loop).
MOV    EAX,0x3c                   ; Move the value 0x3c into EAX.
```

The `LEA` instruction is pointing to the data that interests us. Surely, it looks like it's just loading an address, the actual bytes that were considered the _loaded value_ should be at that memory location. The challenge's requirements is that we need to extract that data. Now it's pretty clear what we have to do. [Radare2](https://rada.re/n/radare2.html) is a solid choice for low-level forensics tasks, debugging, disassembling.

This portable reversing framework is going to allow us for programatic inspection of the binary contents, finds that specific `lea` instruction, and then we can exctract the value from the stack.

In order to understand how we're going to build up our script, we need to understand few radare2 arguments. Check this [list](https://r2wiki.readthedocs.io/en/latest/options/a/af/afl/) for more.

`cmd = 'r2 -q -c "aaa;afl;pdf@entry0" temp.elf > temp'`

```txt
r2 is how we call radare2
-q forces app the quit after done
-c commands to be executed
aaa - analyze all referenced code
afl - all functions list
pdf@entry0 - disassembles function at entry point of binary
temp.elf - this the temp ELF file that is analyzed
temp - redirecting stdout into file
```

This should make all sense what happens above. As final step, we're going to use python's `re` module to search for the regular expression specific pattenr in the radare output we generated. The regexp is `br"0x08048\w{3}`, in order to locate what we need. Yes, we are going to make the assumption that it's always the second match, the one correct. But this becomes pretty clear that all of the ELF files in this challenge are in the same fashion, lots of junk, then in the end the SUB / LEA / MOV / MOVSB instruction scheme. This means we can make that assumption.

This is the entire python script put together that solves all of the challenges in a Speedy Gonzales style. 

```python                                         
#!/usr/bin/env python3

from pwn import *
import base64    
import subprocess
import re

def find_offset(elf_data):
    with open("temp.elf", "wb") as f:
        f.write(elf_data)

    cmd = 'r2 -q -c "aaa;afl;pdf@entry0" temp.elf > temp'
    subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).wait()

    cmd = 'grep "lea" temp'
    output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]

    result = re.findall(br"0x08048\w{3}", output)
    result = result[1]  # assumption is that the second match is correct 
    last = int(result[-3:], 16)

    return last

def calc(elf_b64):
    elf_data = base64.b64decode(elf_b64)
    offset = find_offset(elf_data)
    expected_bytes = elf_data[offset:offset+24]
    return expected_bytes.hex()

context.binary = ELF('./decoded_binary', checksec=False)
context.arch = 'amd64'
context.log_level = 'debug'

p = remote("94.237.49.166", 38409)
p.recvuntil(b'Expected bytes: ')
warmup = p.recvline().strip()
p.sendlineafter(b'Bytes?', warmup)

for i in range(128):
    p.recvuntil(b'ELF: ')
    elf_b64 = p.recvuntil(b'\nBytes? ', drop=True)
    answer = calc(elf_b64)
    p.sendline(answer)

p.interactive()
```

And here's how it runs, it's really fast. Usually it takes less than 10 seconds, around 7-8 seconds for solving all of the 128 challenges. 

![image](https://github.com/respawnRW/writeups/assets/163560495/3eaf614d-423f-46d0-b791-f341386116f4)

Flag: `HTB{y0u_4n4lyz3d_th3_p4tt3ns!}`
