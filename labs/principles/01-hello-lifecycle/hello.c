/**
 * Linux Kernel Hardening Lab - Principles Track 1: Hello World Lifecycle
 * labs/principles/01-hello-lifecycle/hello.c
 *
 * Demonstrates the fundamental structure of a minimal C program,
 * identifying the transition from libc _start to main(),
 * and the final exit_group syscall.
 */

#include <stdio.h>
#include <unistd.h>

/* Global variables to inspect in ELF .data and .rodata */
const char g_greeting[] = "Hello, System Security Principles!";
int g_run_counter = 1;

int main(int argc, char *argv[])
{
    printf("[+] %s\n", g_greeting);
    printf("[+] Process PID: %d, PPID: %d\n", getpid(), getppid());
    printf("[+] main() address: %p\n", (void *)main);
    printf("[+] g_greeting (.rodata): %p\n", (void *)g_greeting);
    printf("[+] g_run_counter (.data): %p (value=%d)\n", (void *)&g_run_counter, g_run_counter);
    printf("[+] argc: %d, argv[0]: %s\n", argc, argv[0]);

    return 0;
}
