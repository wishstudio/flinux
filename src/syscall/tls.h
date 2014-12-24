#pragma once

#include <stdint.h>

#define TLS_KERNEL_ENTRY_COUNT	3
/* Used by dbt */
#define TLS_ENTRY_SCRATCH		0
#define TLS_ENTRY_GS			1
#define TLS_ENTRY_GS_ADDR		2

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

int tls_kernel_entry_to_offset(int entry);
int tls_user_entry_to_offset(int entry);
