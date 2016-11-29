# Debase2

Debase is an
ASLR checker to check if an exe has been complied with ASLR enabled. Debase
will also report if the exe is not a valid exe. 

ASLR:

Address
space layout randomization (ASLR) is a computer security technique involved in
protection from buffer overflow attacks. In order to prevent an attacker from
reliably jumping to, for example, a particular exploited function in memory,
ASLR randomly arranges the address space positions of key data areas of a
process, including the base of the executable and the positions of the stack,
heap and libraries.

Debase is
programmed in C. 

Usage:
debase.exe “filename.exe”

Debase will
simple report if an exe has ASLR enabled or disabled. 

To compile source code use Visual Studio any version. 


