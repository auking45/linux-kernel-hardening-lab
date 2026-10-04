/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/dlopen_demo.c
 *
 * Demonstrates runtime dynamic loading via libdl:
 * dlopen() -> dlsym() -> execution -> dlclose()
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef const char *(*plugin_name_fn)(void);
typedef int (*plugin_exec_fn)(int);

int main(int argc, char *argv[])
{
    const char *lib_path = (argc > 1) ? argv[1] : "./libplugin.so";

    printf("============================================================\n");
    printf(" Runtime Dynamic Loading (dlopen / dlsym Demonstration)\n");
    printf("============================================================\n");
    printf("[+] Opening shared library at runtime: %s\n", lib_path);

    /* Dynamically load library into process memory space */
    void *handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "[-] dlopen failed: %s\n", dlerror());
        return 1;
    }
    printf("[+] Library mapped into address space! Handle: %p\n", handle);

    /* Resolve function symbol pointer via dlsym */
    dlerror(); /* Clear any existing error */
    plugin_name_fn get_name = (plugin_name_fn)dlsym(handle, "plugin_name");
    char *err = dlerror();
    if (err) {
        fprintf(stderr, "[-] dlsym plugin_name failed: %s\n", err);
        dlclose(handle);
        return 1;
    }

    plugin_exec_fn run_exec = (plugin_exec_fn)dlsym(handle, "plugin_execute");
    err = dlerror();
    if (err) {
        fprintf(stderr, "[-] dlsym plugin_execute failed: %s\n", err);
        dlclose(handle);
        return 1;
    }

    printf("[+] Resolved symbol 'plugin_name'    at address: %p\n", (void *)get_name);
    printf("[+] Resolved symbol 'plugin_execute' at address: %p\n\n", (void *)run_exec);

    /* Invoke dynamically loaded functions */
    printf("[*] Plugin Name Result  : %s\n", get_name());
    int result = run_exec(10);
    printf("[*] Plugin Execute Result: %d\n\n", result);

    /* Unload library from address space */
    printf("[+] Calling dlclose(%p) to unmap library...\n", handle);
    dlclose(handle);
    printf("[+] Library safely unmapped from process memory.\n");
    printf("============================================================\n");

    return 0;
}
