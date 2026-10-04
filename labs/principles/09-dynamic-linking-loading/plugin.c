/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/plugin.c
 *
 * Position-Independent Shared Library (-fPIC -shared)
 */

#include <stdio.h>

const char *plugin_name(void)
{
    return "High-Precision Telemetry Sensor Plugin v1.0";
}

int plugin_execute(int input_val)
{
    printf("[libplugin.so] Executing telemetry calculation on input=%d...\n", input_val);
    return input_val * 42 + 7;
}
