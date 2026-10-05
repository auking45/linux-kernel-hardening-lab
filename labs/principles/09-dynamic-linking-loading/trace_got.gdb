# GDB script to trace PLT/GOT Lazy Binding in secvault_dyn
set pagination off
set confirm off

file secvault_dyn
b main
run

echo \n=== [1] BEFORE 1st Call (Lazy Binding Unresolved) ===\n
x/gx (char*)&main - 0x11c9 + 0x4020
x/2i *(void**)((char*)&main - 0x11c9 + 0x4020)

b secvault_dyn.c:28
continue

echo \n=== [2] AFTER 1st Call (Lazy Binding Resolved) ===\n
x/gx (char*)&main - 0x11c9 + 0x4020
info symbol *(void**)((char*)&main - 0x11c9 + 0x4020)

continue
quit
