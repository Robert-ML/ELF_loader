# ELF_loader
Implemented a program file loader for the Linux operating system.

It accepts ELF files and loads their header into memory, while the rest of the .text segment is put into memory on demand using paging and page fault system calls.
