#pragma once

#include <stdint.h>

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

size_t tls_alloc();
int tls_slot_to_offset(int slot);
int tls_offset_to_slot(int offset);
